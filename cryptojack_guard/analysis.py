"""Deterministic cryptojacking rule engine.

The engine turns collected signals into :class:`~cryptojack_guard.models.Signal`
objects. It makes no network calls and no model calls, so its verdict is reproducible
and unit testable; the LLM stages only explain and prioritise what this module decides.

Two invariants keep the output honest:

* Only a threat-detection product can produce ``CONFIRMED`` confidence. Correlated
  telemetry, however damning, tops out at ``HIGH``.
* Preventive gaps always carry ``LOW`` confidence, because a missing guardrail is
  evidence about the future, not evidence that mining is happening now.

Every signal is advisory. ``advisory_commands`` are strings for a human to review; the
agent never executes them.
"""

from __future__ import annotations

from typing import Any

from cryptojack_guard.config import MINING_CATEGORY_MARKERS, PREVENTIVE_CONSTRAINTS, Settings
from cryptojack_guard.config import get_settings as get_cryptojack_settings
from cryptojack_guard.models import (
    STATE_BUDGETS,
    STATE_MONITORING,
    STATE_ORG_POLICIES,
    STATE_QUOTAS,
    STATE_SCC_FINDINGS,
    Confidence,
    Signal,
    SignalKind,
    dedupe_signals,
    sort_signals,
)
from iam_guard.analysis import analyze as analyze_iam
from iam_guard.config import get_settings as get_iam_settings
from iam_guard.models import STATE_GCE, Severity, ThreatCategory
from iam_guard.normalize import dicts, mapping, number, strings, text

#: SCC severities mapped onto our scale; unknown values fall back to MEDIUM.
_SCC_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

#: Broad scopes that hand an attacker the instance's service-account privileges.
_BROAD_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    }
)


def analyze(signals_by_key: dict[str, Any], settings: Settings | None = None) -> list[Signal]:
    """Runs every cryptojacking rule over the collected signals.

    Args:
        signals_by_key: Session state slice keyed by the ``STATE_*`` constants of both
            this package and :mod:`iam_guard`.
        settings: Detection thresholds. Defaults to the environment configuration.

    Returns:
        Deduplicated signals ordered by confidence, then severity.
    """
    settings = settings or get_cryptojack_settings()

    scc = mapping(signals_by_key, STATE_SCC_FINDINGS)
    monitoring = mapping(signals_by_key, STATE_MONITORING)
    quotas = mapping(signals_by_key, STATE_QUOTAS)
    budgets = mapping(signals_by_key, STATE_BUDGETS)
    policies = mapping(signals_by_key, STATE_ORG_POLICIES)
    gce = mapping(signals_by_key, STATE_GCE)

    signals: list[Signal] = []
    signals += _scc_signals(scc)
    signals += _utilization_signals(monitoring, settings)
    signals += _correlation_signals(scc, monitoring, gce, settings)
    signals += _quota_signals(quotas, gce, settings)
    signals += _budget_signals(budgets)
    signals += _policy_signals(policies)
    signals += _iam_precondition_signals(signals_by_key)

    return sort_signals(dedupe_signals(signals))


# --------------------------------------------------------------------------- #
# Detections: Security Command Center
# --------------------------------------------------------------------------- #


def _is_mining_category(category: str) -> bool:
    lowered = category.lower()
    return any(marker in lowered for marker in MINING_CATEGORY_MARKERS)


def _scc_signals(scc: dict[str, Any]) -> list[Signal]:
    """Turns SCC threat findings into detections.

    A mining-specific category is the only thing in this whole engine that justifies
    ``CONFIRMED``: Event Threat Detection matched a known pool domain or hash, or VM
    Threat Detection matched mining software in guest memory.
    """
    project_id = text(scc, "project_id", "unknown-project")
    signals: list[Signal] = []
    # Several mining findings on one instance are one incident, not several. They are
    # merged so the evidence stays together instead of being deduplicated away.
    mining_by_resource: dict[str, list[dict[str, Any]]] = {}

    for finding in dicts(scc, "findings"):
        category = text(finding, "category")
        if not category:
            continue
        resource = text(finding, "resource_name", f"projects/{project_id}")
        severity = _SCC_SEVERITY.get(text(finding, "severity").upper(), Severity.MEDIUM)
        evidence = {
            "category": category,
            "finding_name": text(finding, "name"),
            "finding_class": text(finding, "finding_class"),
            "scc_severity": text(finding, "severity"),
            "event_time": text(finding, "event_time"),
            "description": text(finding, "description"),
            "scc_next_steps": text(finding, "next_steps"),
        }
        if _is_mining_category(category):
            mining_by_resource.setdefault(resource, []).append(evidence)
        elif text(finding, "finding_class").upper() == "THREAT":
            signals.append(
                Signal(
                    rule_id="CJ-SCC-THREAT-FINDING",
                    title=f"Active Security Command Center threat finding: {category}",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    kind=SignalKind.DETECTION,
                    source="scc",
                    resource=resource,
                    explanation=(
                        "This finding is not mining specific, but cryptojacking rarely "
                        "arrives alone: the same foothold that installs a miner shows up "
                        "first as malware, a suspicious login, or an unexpected binary. "
                        "It is corroborating context, not proof of mining."
                    ),
                    investigation=(
                        "Work the finding on its own merits in Security Command Center, "
                        "then check whether the affected resource also appears in this "
                        "report's utilisation or quota signals."
                    ),
                    remediation=(
                        "Follow the next steps published with the finding. Prioritise it "
                        "above the preventive gaps in this report if it affects an "
                        "instance that also shows sustained saturation."
                    ),
                    evidence=evidence,
                    advisory_commands=[],
                )
            )

    for resource, findings in sorted(mining_by_resource.items()):
        categories = sorted({str(entry["category"]) for entry in findings})
        signals.append(
            Signal(
                rule_id="CJ-SCC-MINING-DETECTION",
                title=("Security Command Center detected cryptomining: " + ", ".join(categories)),
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                kind=SignalKind.DETECTION,
                source="scc",
                resource=resource,
                explanation=(
                    "Security Command Center matched this workload against known "
                    "cryptomining indicators (pool domains and IPs, mining binary "
                    "hashes, or mining software found in guest memory by VM Threat "
                    "Detection). Unlike utilisation or quota signals, this names "
                    "mining specifically, so treat it as an active incident rather "
                    "than a tuning question."
                ),
                investigation=(
                    "Read the finding in Security Command Center, identify the "
                    "process and the destination it connects to, and check who "
                    "created the instance and with which credentials: "
                    "look for the instances.insert entry in Cloud Audit Logs to find "
                    "the principal, then review that principal's other activity."
                ),
                remediation=(
                    "Contain the workload and remove the access that created it. "
                    "Snapshot the boot disk before deleting anything so the "
                    "investigation is not destroyed, then stop the instance, revoke "
                    "the credentials of the principal that launched it, and rotate "
                    "any key that principal held."
                ),
                evidence={"categories": categories, "findings": findings},
                advisory_commands=_containment_commands(resource),
            )
        )
    return signals


def _containment_commands(resource: str) -> list[str]:
    """Builds the advisory containment sequence for a suspect instance.

    Ordering matters and is deliberate: preserve evidence, then stop the compute, then
    cut the identity. The agent emits these; a human applies them.
    """
    instance, zone = _instance_and_zone(resource)
    if not instance or not zone:
        return [
            "# Identify the affected instance from the finding, then snapshot its disk "
            "before stopping it.",
        ]
    return [
        f"gcloud compute disks snapshot {instance} --zone={zone} "
        f"--snapshot-names={instance}-forensics  # preserve evidence first",
        f"gcloud compute instances stop {instance} --zone={zone}  # after the snapshot",
        f'gcloud logging read \'protoPayload.methodName="v1.compute.instances.insert" '
        f'AND protoPayload.resourceName:"instances/{instance}"\' '
        "--limit=5 --format='value(protoPayload.authenticationInfo.principalEmail)'"
        "  # who launched it",
    ]


def _instance_and_zone(resource: str) -> tuple[str, str]:
    """Parses ``.../zones/<zone>/instances/<name>`` out of an SCC resource name."""
    parts = resource.split("/")
    instance = ""
    zone = ""
    for index, part in enumerate(parts[:-1]):
        if part == "instances":
            instance = parts[index + 1]
        elif part == "zones":
            zone = parts[index + 1]
    return instance, zone


# --------------------------------------------------------------------------- #
# Detections: utilisation
# --------------------------------------------------------------------------- #


def _utilization_signals(monitoring: dict[str, Any], settings: Settings) -> list[Signal]:
    """Flags instances that are pinned for long enough to be mining.

    Both halves of the test matter. A high mean alone catches a batch job; requiring
    the utilisation to stay above the threshold for ``cpu_sustained_minutes`` is what
    separates "busy" from "pinned", which is the shape mining has.
    """
    project_id = text(monitoring, "project_id", "unknown-project")
    threshold = number(monitoring, "cpu_threshold", settings.cpu_threshold)
    signals: list[Signal] = []
    for instance in dicts(monitoring, "instances"):
        name = text(instance, "instance")
        if not name:
            continue
        zone = text(instance, "zone")
        resource = f"//compute.googleapis.com/projects/{project_id}/instances/{name}"
        mean_cpu = number(instance, "mean_cpu_utilization", -1.0)
        sustained = number(instance, "minutes_above_cpu_threshold")
        if mean_cpu >= threshold and sustained >= settings.cpu_sustained_minutes:
            signals.append(
                Signal(
                    rule_id="CJ-MON-SUSTAINED-CPU",
                    title=f"{name} held CPU above {threshold:.0%} for {int(sustained)} minutes",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    kind=SignalKind.DETECTION,
                    source="monitoring",
                    resource=resource,
                    explanation=(
                        "Mining is a flat, uninterrupted CPU load, so sustained "
                        "saturation is the cheapest signal available. It is not "
                        "conclusive: batch rendering, video transcoding, CI runners and "
                        "load tests look identical from the hypervisor. Treat it as a "
                        "question to answer about a specific instance."
                    ),
                    investigation=(
                        f"Confirm the workload is expected: check who owns {name}, "
                        "whether its labels or instance group match a known pipeline, "
                        "and what its top processes are. If the owner is unknown or the "
                        "instance was created outside your usual automation, escalate."
                    ),
                    remediation=(
                        "If the workload is legitimate, exclude the instance by raising "
                        "CRYPTOJACK_GUARD_CPU_THRESHOLD or by scoping this check to "
                        "unlabelled instances. If it is not, snapshot the disk and stop "
                        "the instance."
                    ),
                    evidence={
                        "zone": zone,
                        "mean_cpu_utilization": mean_cpu,
                        "max_cpu_utilization": number(instance, "max_cpu_utilization"),
                        "minutes_above_threshold": sustained,
                        "cpu_threshold": threshold,
                        "lookback_hours": number(
                            monitoring, "lookback_hours", settings.lookback_hours
                        ),
                    },
                    advisory_commands=_containment_commands(
                        f"projects/{project_id}/zones/{zone}/instances/{name}"
                    ),
                )
            )

        mean_gpu = number(instance, "mean_gpu_utilization", -1.0)
        if mean_gpu >= settings.gpu_threshold:
            signals.append(
                Signal(
                    rule_id="CJ-MON-GPU-SATURATION",
                    title=f"{name} shows sustained GPU utilisation of {mean_gpu:.0%}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    kind=SignalKind.DETECTION,
                    source="monitoring",
                    resource=resource,
                    explanation=(
                        "Saturated accelerators are attractive to miners and expensive "
                        "to leave running. On its own this is weak evidence, because "
                        "any GPU worth attaching is usually worth saturating: ML "
                        "training looks the same."
                    ),
                    investigation=(
                        f"Check whether {name} belongs to a known training or inference "
                        "workload, and whether its GPU type matches what that workload "
                        "requests."
                    ),
                    remediation=(
                        "Confirm ownership. If the instance is unexplained, treat it as "
                        "a suspected miner and follow the containment sequence."
                    ),
                    evidence={
                        "zone": zone,
                        "mean_gpu_utilization": mean_gpu,
                        "max_gpu_utilization": number(instance, "max_gpu_utilization"),
                        "gpu_threshold": settings.gpu_threshold,
                    },
                    advisory_commands=[],
                )
            )
    return signals


# --------------------------------------------------------------------------- #
# Detections: correlation
# --------------------------------------------------------------------------- #


def _correlation_signals(
    scc: dict[str, Any],
    monitoring: dict[str, Any],
    gce: dict[str, Any],
    settings: Settings,
) -> list[Signal]:
    """Raises confidence where independent signals point at the same instance.

    One saturated VM is a tuning question. A saturated VM that also has a public IP and
    a broadly scoped service account is the full cryptojacking shape: capacity to mine,
    a path to the pool, and credentials to spread. That combination is what earns
    ``HIGH`` confidence without a threat-detection product.
    """
    project_id = text(monitoring, "project_id") or text(gce, "project_id", "unknown-project")
    threshold = number(monitoring, "cpu_threshold", settings.cpu_threshold)
    instances_by_name = {
        text(instance, "name"): instance
        for instance in dicts(gce, "instances")
        if text(instance, "name")
    }
    scc_resources = {
        text(finding, "resource_name")
        for finding in dicts(scc, "findings")
        if _is_mining_category(text(finding, "category"))
    }

    signals: list[Signal] = []
    for measured in dicts(monitoring, "instances"):
        name = text(measured, "instance")
        if not name:
            continue
        saturated = (
            number(measured, "mean_cpu_utilization", -1.0) >= threshold
            and number(measured, "minutes_above_cpu_threshold") >= settings.cpu_sustained_minutes
        ) or number(measured, "mean_gpu_utilization", -1.0) >= settings.gpu_threshold
        if not saturated:
            continue

        instance = instances_by_name.get(name)
        if instance is None:
            continue
        zone = text(instance, "zone") or text(measured, "zone")
        resource = f"//compute.googleapis.com/projects/{project_id}/zones/{zone}/instances/{name}"
        external_ips = strings(instance, "external_ips")
        broad_scoped = sorted(
            {
                text(sa, "email")
                for sa in dicts(instance, "service_accounts")
                if _BROAD_SCOPES & set(strings(sa, "scopes"))
            }
            - {""}
        )
        named_by_scc = any(
            name in resource_name for resource_name in scc_resources if resource_name
        )

        if named_by_scc:
            signals.append(
                Signal(
                    rule_id="CJ-CORR-CONFIRMED-MINER",
                    title=f"{name} is both flagged by SCC and running saturated",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    kind=SignalKind.DETECTION,
                    source="correlation",
                    resource=resource,
                    explanation=(
                        "Security Command Center named this instance in a cryptomining "
                        "finding and its telemetry shows the matching resource burn. "
                        "There is no benign reading of these two together: the workload "
                        "is mining."
                    ),
                    investigation=(
                        "Skip triage and move to response. Capture the evidence you need "
                        "for the incident record, then determine the entry point from "
                        "the audit log before the credentials are reused elsewhere."
                    ),
                    remediation=(
                        "Snapshot, stop, and revoke, in that order. Then close the entry "
                        "point: the preventive gaps in this report are how it happened."
                    ),
                    evidence={
                        "zone": zone,
                        "mean_cpu_utilization": number(measured, "mean_cpu_utilization"),
                        "mean_gpu_utilization": number(measured, "mean_gpu_utilization"),
                        "external_ips": external_ips,
                        "broadly_scoped_service_accounts": broad_scoped,
                    },
                    advisory_commands=_containment_commands(
                        f"projects/{project_id}/zones/{zone}/instances/{name}"
                    ),
                )
            )
        elif external_ips and broad_scoped:
            signals.append(
                Signal(
                    rule_id="CJ-CORR-SATURATED-EXPOSED-PRIVILEGED",
                    title=(
                        f"{name} is saturated, internet reachable and holds a broadly "
                        "scoped service account"
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    kind=SignalKind.DETECTION,
                    source="correlation",
                    resource=resource,
                    explanation=(
                        "Three independent facts line up on one instance: it is burning "
                        "capacity, it can reach the internet directly (a miner needs a "
                        "pool), and it carries credentials broad enough to create more "
                        "instances if compromised. Each is individually explainable; "
                        "together they are the standard cryptojacking configuration and "
                        "the blast radius if it is real is the whole project."
                    ),
                    investigation=(
                        f"Identify the owner of {name} and confirm the load is expected. "
                        "Inspect its outbound connections for mining-pool destinations, "
                        "and check the audit log for what its service account has done "
                        "recently, especially instances.insert calls."
                    ),
                    remediation=(
                        "Reduce the instance's privilege and reachability even if the "
                        "load turns out to be legitimate: replace the broad scope with a "
                        "dedicated service account holding only the roles it needs, and "
                        "remove the external IP in favour of Cloud NAT. If the load is "
                        "not explained, contain it first."
                    ),
                    evidence={
                        "zone": zone,
                        "mean_cpu_utilization": number(measured, "mean_cpu_utilization"),
                        "minutes_above_threshold": number(measured, "minutes_above_cpu_threshold"),
                        "mean_gpu_utilization": number(measured, "mean_gpu_utilization"),
                        "external_ips": external_ips,
                        "broadly_scoped_service_accounts": broad_scoped,
                        "machine_type": text(instance, "machine_type"),
                        "gpu_count": number(instance, "gpu_count"),
                    },
                    advisory_commands=[
                        *_containment_commands(
                            f"projects/{project_id}/zones/{zone}/instances/{name}"
                        ),
                        f"gcloud compute instances delete-access-config {name} "
                        f"--zone={zone} --access-config-name='external-nat'"
                        "  # only after confirming the workload does not need it",
                    ],
                )
            )
    return signals


# --------------------------------------------------------------------------- #
# Detections: capacity
# --------------------------------------------------------------------------- #


def _quota_signals(quotas: dict[str, Any], gce: dict[str, Any], settings: Settings) -> list[Signal]:
    """Flags CPU and GPU capacity being consumed, especially in unused regions.

    Quota usage is the one signal that catches mining you cannot see per instance,
    because it aggregates whatever the attacker created. Usage in a region where the
    inventory shows no instances is the interesting case: nobody deploys there, so
    something else is.
    """
    project_id = text(quotas, "project_id", "unknown-project")
    threshold = number(quotas, "quota_usage_threshold", settings.quota_usage_threshold)
    used_regions = {
        text(instance, "zone").rsplit("-", 1)[0]
        for instance in dicts(gce, "instances")
        if text(instance, "zone")
    }
    inventory_known = bool(dicts(gce, "instances"))

    signals: list[Signal] = []
    for region_record in dicts(quotas, "regions"):
        region = text(region_record, "region")
        if not region:
            continue
        for quota in dicts(region_record, "quotas"):
            metric = text(quota, "metric")
            limit = number(quota, "limit")
            usage = number(quota, "usage")
            if not metric or limit <= 0 or usage <= 0:
                continue
            ratio = usage / limit
            unexpected_region = inventory_known and region not in used_regions
            if not unexpected_region and ratio < threshold:
                continue

            resource = f"//compute.googleapis.com/projects/{project_id}/regions/{region}"
            evidence = {
                "region": region,
                "metric": metric,
                "usage": usage,
                "limit": limit,
                "utilization": round(ratio, 3),
                "regions_with_inventory": sorted(used_regions),
            }
            if unexpected_region:
                signals.append(
                    Signal(
                        rule_id="CJ-QUOTA-UNEXPECTED-REGION",
                        title=f"{metric} capacity is in use in {region}, where you run nothing",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        kind=SignalKind.DETECTION,
                        source="compute",
                        resource=resource,
                        explanation=(
                            "Compute capacity is being consumed in a region that holds "
                            "none of the instances this audit inventoried. Attackers "
                            "deliberately pick regions their victim does not watch. The "
                            "innocent explanations are a workload the inventory could not "
                            "read (permissions or instance caps) or resources other than "
                            "VMs holding the quota."
                        ),
                        investigation=(
                            f"List everything in {region} and check the audit log for who "
                            "created it."
                        ),
                        remediation=(
                            "Delete what should not be there, then stop the region being "
                            "usable: cap its CPU and GPU quota to zero so a future "
                            "attacker cannot use it either."
                        ),
                        evidence=evidence,
                        advisory_commands=[
                            f"gcloud compute instances list --filter='zone~{region}'",
                            f"gcloud logging read 'protoPayload.methodName="
                            f'"v1.compute.instances.insert" AND resource.labels.zone~"{region}"\' '
                            "--limit=20 "
                            "--format='table(protoPayload.authenticationInfo.principalEmail,"
                            "protoPayload.resourceName)'",
                            f"# Then request a quota cap for {metric} in {region} via "
                            "the Quotas page or the Service Usage API "
                            "(quota changes are not applied by this agent).",
                        ],
                    )
                )
            else:
                signals.append(
                    Signal(
                        rule_id="CJ-QUOTA-NEAR-LIMIT",
                        title=(f"{metric} in {region} is at {ratio:.0%} of its quota limit"),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        kind=SignalKind.DETECTION,
                        source="compute",
                        resource=resource,
                        explanation=(
                            "Near-limit capacity matters for two reasons: it caps how "
                            "much a hijacker could add, and it is what makes a "
                            "cryptojacking bill large. This is a posture observation, "
                            "not evidence of abuse: a busy project sits here normally."
                        ),
                        investigation=(
                            "Compare the consumed capacity against what your workloads "
                            "should need in this region."
                        ),
                        remediation=(
                            "Keep quota at the smallest value your workloads need. "
                            "Unused CPU and GPU quota is standing capacity for an "
                            "attacker, and quota is the only hard cap on how expensive a "
                            "cryptojacking incident can get."
                        ),
                        evidence=evidence,
                        advisory_commands=[
                            f"gcloud compute regions describe {region} "
                            "--format='table(quotas.metric,quotas.usage,quotas.limit)'",
                        ],
                    )
                )
    return signals


# --------------------------------------------------------------------------- #
# Preventive gaps
# --------------------------------------------------------------------------- #


def _budget_signals(budgets: dict[str, Any]) -> list[Signal]:
    """Checks that a budget with notifications covers the project.

    Spend is the signal victims actually notice, usually weeks late. A budget with
    threshold notifications turns that into hours.
    """
    # No budget data at all means the collector could not read billing. Reporting that
    # as "no budget exists" would be a false finding built on missing evidence.
    if not isinstance(budgets.get("budgets"), list):
        return []

    project_id = text(budgets, "project_id", "unknown-project")
    resource = f"//cloudbilling.googleapis.com/projects/{project_id}"
    covering = [
        budget
        for budget in dicts(budgets, "budgets")
        # An empty project filter means the budget covers the whole billing account,
        # which includes this project.
        if not strings(budget, "projects")
        or any(project_id in entry for entry in strings(budget, "projects"))
    ]
    if not covering:
        return [
            Signal(
                rule_id="CJ-BILLING-NO-BUDGET",
                title="No Cloud Billing budget covers this project",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                kind=SignalKind.PREVENTIVE,
                source="billing",
                resource=resource,
                explanation=(
                    "Without a budget, a hijacked project mines until someone reads an "
                    "invoice. A budget with threshold alerts is the single highest-value "
                    "cryptojacking control available, because unexpected spend is the "
                    "one symptom every mining campaign has."
                ),
                investigation=(
                    "Confirm the project's billing account and whether alerting is "
                    "handled by another system."
                ),
                remediation=(
                    "Create a budget scoped to this project with alert thresholds well "
                    "below the level you would consider normal, and route the "
                    "notifications to a channel someone reads out of hours."
                ),
                evidence={"budgets_found": len(dicts(budgets, "budgets"))},
                advisory_commands=[
                    "gcloud billing budgets create "
                    "--billing-account=BILLING_ACCOUNT_ID "
                    f"--display-name='cryptojacking tripwire {project_id}' "
                    f"--filter-projects=projects/{project_id} "
                    "--budget-amount=AMOUNT --threshold-rule=percent=0.5 "
                    "--threshold-rule=percent=0.9",
                ],
            )
        ]
    if not any(budget.get("notifications_configured") for budget in covering):
        return [
            Signal(
                rule_id="CJ-BILLING-BUDGET-WITHOUT-ALERTS",
                title="Budgets cover this project but notify nobody",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                kind=SignalKind.PREVENTIVE,
                source="billing",
                resource=resource,
                explanation=(
                    "A budget with no notification channel or Pub/Sub topic only shows a "
                    "number in the console. Nobody watches the console during the hours "
                    "when mining runs cheapest."
                ),
                investigation=(
                    "Check each covering budget for a Pub/Sub topic or monitoring "
                    "notification channel."
                ),
                remediation=(
                    "Attach a notification channel or Pub/Sub topic to the budget and "
                    "verify an alert actually arrives."
                ),
                evidence={"budgets": [text(budget, "display_name") for budget in covering]},
                advisory_commands=[
                    "gcloud billing budgets update BUDGET_ID "
                    "--billing-account=BILLING_ACCOUNT_ID "
                    "--notifications-rule-pubsub-topic=projects/"
                    f"{project_id}/topics/budget-alerts",
                ],
            )
        ]
    return []


#: Severity per preventive constraint. Key creation leads because exported keys are the
#: most common way projects get hijacked; the rest are defence in depth.
_CONSTRAINT_SEVERITY = {
    "constraints/iam.disableServiceAccountKeyCreation": Severity.HIGH,
    "constraints/compute.vmExternalIpAccess": Severity.MEDIUM,
    "constraints/compute.requireOsLogin": Severity.MEDIUM,
    "constraints/compute.disableSerialPortAccess": Severity.LOW,
    "constraints/compute.disableNestedVirtualization": Severity.LOW,
}


def _policy_signals(policies: dict[str, Any]) -> list[Signal]:
    """Reports which preventive org policy constraints are not enforced."""
    project_id = text(policies, "project_id", "unknown-project")
    constraints = policies.get("constraints")
    if not isinstance(constraints, dict):
        return []

    signals: list[Signal] = []
    for constraint, rationale in sorted(PREVENTIVE_CONSTRAINTS.items()):
        state = constraints.get(constraint)
        if not isinstance(state, dict):
            continue
        if state.get("enforced"):
            continue
        short_name = constraint.rsplit("/", 1)[-1]
        signals.append(
            Signal(
                rule_id=f"CJ-POLICY-{short_name.replace('.', '-').upper()}",
                title=f"Org policy {short_name} is not enforced",
                severity=_CONSTRAINT_SEVERITY.get(constraint, Severity.LOW),
                confidence=Confidence.LOW,
                kind=SignalKind.PREVENTIVE,
                source="org_policy",
                resource=f"//cloudresourcemanager.googleapis.com/projects/{project_id}",
                explanation=rationale,
                investigation=(
                    "Check whether any current workload depends on the behaviour this "
                    "constraint blocks, and whether a folder or organisation level "
                    "policy already covers it for other projects."
                ),
                remediation=(
                    "Enforce the constraint at the folder or organisation level so new "
                    "projects inherit it, with per-project exceptions where a workload "
                    "genuinely needs the behaviour."
                ),
                evidence={
                    "constraint": constraint,
                    "effective_policy": text(state, "detail", "not enforced"),
                },
                advisory_commands=[
                    f"gcloud resource-manager org-policies describe {constraint} "
                    f"--project={project_id}",
                    f"# Then enforce it after checking for dependencies, ideally on the "
                    f"folder or organisation rather than the project: "
                    f"gcloud resource-manager org-policies enable-enforce {constraint} "
                    f"--project={project_id}",
                ],
            )
        )
    return signals


def _iam_precondition_signals(signals_by_key: dict[str, Any]) -> list[Signal]:
    """Reuses IAM Guard's rule engine for the identity preconditions of cryptojacking.

    Rather than reimplementing IAM analysis, this runs the existing engine over the same
    session state and keeps only the findings it already categorises as cryptojacking
    exposure: who can create compute, which keys could be stolen, which instances hand
    out project-wide credentials. They are preventive by definition, so they carry LOW
    confidence and never influence the mining verdict.
    """
    iam_findings = analyze_iam(signals_by_key, get_iam_settings())
    signals: list[Signal] = []
    for finding in iam_findings:
        if ThreatCategory.CRYPTOJACKING not in finding.categories:
            continue
        signals.append(
            Signal(
                rule_id=f"CJ-IAM-{finding.rule_id}",
                title=finding.title,
                severity=finding.severity,
                confidence=Confidence.LOW,
                kind=SignalKind.PREVENTIVE,
                source="iam",
                resource=finding.resource,
                explanation=(
                    f"{finding.explanation} This is a precondition for cryptojacking "
                    "rather than evidence of it: it describes who could start mining "
                    "workloads or steal the credentials to do so."
                ),
                investigation=(
                    "Confirm each implicated principal still needs this access, and "
                    "check the audit log for compute creation by principals that should "
                    "not be creating compute."
                ),
                remediation=finding.remediation,
                evidence={
                    **finding.evidence,
                    "iam_guard_rule": finding.rule_id,
                    "principals": finding.principals,
                    "roles": finding.roles,
                },
                advisory_commands=list(finding.remediation_commands),
            )
        )
    return signals
