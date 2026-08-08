"""Read-only cryptojacking signal collectors.

Every function here calls list/get style APIs only. Nothing in this module stops a
VM, revokes a key, edits IAM, changes a quota, touches a budget or sets an org policy:
Cryptojack Guard is advisory, so containment stays with a human.

Each collector writes its full result into session state for the deterministic rule
engine and returns a small summary to the model. Credential, permission and API-tier
problems (SCC findings need Security Command Center, and VM Threat Detection needs the
Premium or Enterprise tier) are recorded as collection errors so the report can say
what could not be checked instead of silently reporting "clean".

Set ``CRYPTOJACK_GUARD_FIXTURE=/path/to/signals.json`` to run against recorded signals
instead of live APIs; that is what the tests and the offline demo use.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from google.adk.tools import ToolContext
from google.cloud import compute_v1, monitoring_v3, orgpolicy_v2, securitycenter_v1
from google.cloud.billing import budgets_v1

from cryptojack_guard.config import FIXTURE_ENV_VAR, PREVENTIVE_CONSTRAINTS, get_settings
from cryptojack_guard.models import (
    STATE_BUDGETS,
    STATE_MONITORING,
    STATE_ORG_POLICIES,
    STATE_QUOTAS,
    STATE_SCC_FINDINGS,
)
from iam_guard.tools.session_state import (
    COLLECTION_ERRORS,
    load_fixture,
    missing_project,
    record_inventory,
    tool_failure,
)

#: Compute quota metrics that gate mining capacity. Miners want cores and GPUs.
CAPACITY_QUOTA_METRICS = frozenset(
    {
        "CPUS",
        "CPUS_ALL_REGIONS",
        "GPUS_ALL_REGIONS",
        "NVIDIA_A100_GPUS",
        "NVIDIA_H100_GPUS",
        "NVIDIA_K80_GPUS",
        "NVIDIA_L4_GPUS",
        "NVIDIA_P100_GPUS",
        "NVIDIA_P4_GPUS",
        "NVIDIA_T4_GPUS",
        "NVIDIA_V100_GPUS",
        "PREEMPTIBLE_CPUS",
        "PREEMPTIBLE_NVIDIA_A100_GPUS",
        "PREEMPTIBLE_NVIDIA_T4_GPUS",
    }
)

#: Built-in hypervisor-level CPU metric; present for every VM with no agent installed.
CPU_METRIC = "compute.googleapis.com/instance/cpu/utilization"

#: GPU utilisation is only reported by the Ops Agent, so it is optional: absence means
#: "not measured", never "not saturated".
GPU_METRIC = "agent.googleapis.com/gpu/utilization"


def _resolve_project(project_id: str) -> str:
    return project_id or get_settings().default_project_id


def _load_fixture(
    section: str, tool_context: ToolContext | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    return load_fixture(FIXTURE_ENV_VAR, section, tool_context)


def collect_scc_findings(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists active Security Command Center threat findings for a project.

    These are the only signals that can confirm mining: Event Threat Detection and VM
    Threat Detection name the workload (for example ``Execution: Cryptocurrency Mining
    Hash Match``). Memory-based VM Threat Detection requires the SCC Premium or
    Enterprise tier, so an empty result on the Standard tier is inconclusive.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with the finding count and the mining-related categories seen.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return missing_project()
    settings = get_settings()

    inventory, unusable_fixture = _load_fixture(STATE_SCC_FINDINGS, tool_context)
    if unusable_fixture is not None:
        return unusable_fixture
    if inventory is None:
        try:
            client = securitycenter_v1.SecurityCenterClient()
            request = securitycenter_v1.ListFindingsRequest(
                parent=f"projects/{project_id}/sources/-",
                filter='state="ACTIVE"',
                page_size=min(settings.max_findings, 1000),
            )
            findings = []
            for result in client.list_findings(request=request):
                finding = result.finding
                findings.append(
                    {
                        "name": finding.name,
                        "category": finding.category,
                        "severity": securitycenter_v1.Finding.Severity(finding.severity).name,
                        "state": securitycenter_v1.Finding.State(finding.state).name,
                        "finding_class": securitycenter_v1.Finding.FindingClass(
                            finding.finding_class
                        ).name,
                        "resource_name": finding.resource_name,
                        "event_time": (finding.event_time.rfc3339() if finding.event_time else ""),
                        "description": finding.description,
                        "next_steps": finding.next_steps,
                    }
                )
                if len(findings) >= settings.max_findings:
                    break
        except COLLECTION_ERRORS as error:
            return tool_failure(
                tool_context,
                STATE_SCC_FINDINGS,
                error,
                "Enable Security Command Center and grant the agent "
                "roles/securitycenter.findingsViewer. Memory-based miner detection "
                "additionally needs the SCC Premium or Enterprise tier.",
            )
        inventory = {"project_id": project_id, "findings": findings}

    record_inventory(tool_context, STATE_SCC_FINDINGS, inventory)
    findings = [f for f in inventory.get("findings") or [] if isinstance(f, dict)]
    return {
        "status": "ok",
        "project_id": project_id,
        "finding_count": len(findings),
        "categories": sorted({str(f.get("category", "")) for f in findings if f.get("category")}),
    }


def collect_monitoring_signals(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Reads per-instance CPU and GPU utilisation over the configured lookback window.

    Mining is characterised by utilisation that is both very high and very flat. This
    collector therefore records the mean, the max and how long each instance stayed
    above the CPU threshold, so the rule engine can distinguish a sustained pin from a
    short legitimate spike.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with the number of instances measured and how many look pinned.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return missing_project()
    settings = get_settings()

    inventory, unusable_fixture = _load_fixture(STATE_MONITORING, tool_context)
    if unusable_fixture is not None:
        return unusable_fixture
    if inventory is None:
        try:
            client = monitoring_v3.MetricServiceClient()
            end = dt.datetime.now(tz=dt.timezone.utc)
            interval = monitoring_v3.TimeInterval(
                start_time=end - dt.timedelta(hours=settings.lookback_hours),
                end_time=end,
            )
            cpu = _aligned_series(client, project_id, CPU_METRIC, interval)
            gpu = _aligned_series(client, project_id, GPU_METRIC, interval)
        except COLLECTION_ERRORS as error:
            return tool_failure(
                tool_context,
                STATE_MONITORING,
                error,
                "Enable the Monitoring API and grant the agent roles/monitoring.viewer.",
            )
        inventory = {
            "project_id": project_id,
            "lookback_hours": settings.lookback_hours,
            "cpu_threshold": settings.cpu_threshold,
            "gpu_metric_available": bool(gpu),
            "instances": _merge_series(cpu, gpu, settings.cpu_threshold)[: settings.max_instances],
        }

    record_inventory(tool_context, STATE_MONITORING, inventory)
    instances = [i for i in inventory.get("instances") or [] if isinstance(i, dict)]
    threshold = inventory.get("cpu_threshold", settings.cpu_threshold)
    pinned = [
        i
        for i in instances
        if isinstance(i.get("mean_cpu_utilization"), (int, float))
        and i["mean_cpu_utilization"] >= threshold
    ]
    return {
        "status": "ok",
        "project_id": project_id,
        "instances_measured": len(instances),
        "instances_above_cpu_threshold": len(pinned),
        "gpu_metric_available": bool(inventory.get("gpu_metric_available")),
    }


def _aligned_series(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    metric_type: str,
    interval: monitoring_v3.TimeInterval,
) -> dict[str, dict[str, Any]]:
    """Aligns one metric to 5-minute means per instance.

    Aligning server-side keeps the payload small and makes "sustained" measurable:
    each aligned point represents five minutes, so counting points above the threshold
    yields minutes above the threshold.
    """
    request = monitoring_v3.ListTimeSeriesRequest(
        name=f"projects/{project_id}",
        filter=f'metric.type = "{metric_type}"',
        interval=interval,
        view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        aggregation=monitoring_v3.Aggregation(
            alignment_period=dt.timedelta(minutes=5),
            per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
        ),
    )
    series: dict[str, dict[str, Any]] = {}
    for entry in client.list_time_series(request=request):
        labels = dict(entry.resource.labels)
        # The gce_instance monitored resource is keyed by numeric instance_id; the
        # human readable name only arrives as a system label, and correlating with the
        # Compute inventory needs it.
        system_labels = dict(entry.metadata.system_labels) if entry.metadata else {}
        instance_id = labels.get("instance_id", "")
        name = str(system_labels.get("name") or labels.get("instance_name") or instance_id)
        values = [point.value.double_value for point in entry.points]
        if not values or not name:
            continue
        series[name] = {
            "instance": name,
            "instance_id": instance_id,
            "zone": labels.get("zone", ""),
            "values": values,
        }
    return series


def _merge_series(
    cpu: dict[str, dict[str, Any]],
    gpu: dict[str, dict[str, Any]],
    cpu_threshold: float,
) -> list[dict[str, Any]]:
    """Folds the aligned CPU and GPU series into one record per instance."""
    instances = []
    for name in sorted(set(cpu) | set(gpu)):
        cpu_values = cpu.get(name, {}).get("values") or []
        gpu_values = gpu.get(name, {}).get("values") or []
        zone = cpu.get(name, {}).get("zone") or gpu.get(name, {}).get("zone") or ""
        record: dict[str, Any] = {
            "instance": name,
            "instance_id": cpu.get(name, {}).get("instance_id")
            or gpu.get(name, {}).get("instance_id")
            or "",
            "zone": zone,
            "sample_count": len(cpu_values),
        }
        if cpu_values:
            record["mean_cpu_utilization"] = sum(cpu_values) / len(cpu_values)
            record["max_cpu_utilization"] = max(cpu_values)
            # Each aligned sample covers a 5 minute window.
            record["minutes_above_cpu_threshold"] = (
                sum(1 for value in cpu_values if value >= cpu_threshold) * 5
            )
        if gpu_values:
            record["mean_gpu_utilization"] = sum(gpu_values) / len(gpu_values)
            record["max_gpu_utilization"] = max(gpu_values)
        instances.append(record)
    return instances


def collect_compute_quotas(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Reads per-region Compute Engine CPU and GPU quota usage against its limit.

    Capacity consumption is how cryptojacking becomes expensive. A project sitting at
    its CPU or GPU limit in a region nobody deploys to is a strong hint; a project at
    its limit in its normal region is just busy.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with the regions read and the highest capacity utilisation seen.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return missing_project()
    settings = get_settings()

    inventory, unusable_fixture = _load_fixture(STATE_QUOTAS, tool_context)
    if unusable_fixture is not None:
        return unusable_fixture
    if inventory is None:
        try:
            client = compute_v1.RegionsClient()
            regions = []
            for region in client.list(project=project_id):
                quotas = [
                    {
                        "metric": quota.metric,
                        "limit": quota.limit,
                        "usage": quota.usage,
                    }
                    for quota in region.quotas
                    if quota.metric in CAPACITY_QUOTA_METRICS and quota.limit
                ]
                if quotas:
                    regions.append({"region": region.name, "quotas": quotas})
        except COLLECTION_ERRORS as error:
            return tool_failure(
                tool_context,
                STATE_QUOTAS,
                error,
                "Grant the agent roles/compute.viewer on the project.",
            )
        inventory = {
            "project_id": project_id,
            "quota_usage_threshold": settings.quota_usage_threshold,
            "regions": regions,
        }

    record_inventory(tool_context, STATE_QUOTAS, inventory)
    regions = [r for r in inventory.get("regions") or [] if isinstance(r, dict)]
    ratios = [
        quota["usage"] / quota["limit"]
        for region in regions
        for quota in region.get("quotas") or []
        if isinstance(quota, dict)
        and isinstance(quota.get("usage"), (int, float))
        and isinstance(quota.get("limit"), (int, float))
        and quota["limit"]
    ]
    return {
        "status": "ok",
        "project_id": project_id,
        "regions_read": len(regions),
        "max_quota_utilization": round(max(ratios), 3) if ratios else 0.0,
    }


def collect_billing_budgets(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists Cloud Billing budgets that cover the project.

    A budget with threshold notifications is the cheapest cryptojacking tripwire there
    is: mining shows up as spend long before anyone reads a log. Its absence is a
    preventive gap, not evidence of abuse.

    Args:
        project_id: Project the budgets should cover. Defaults to the configured project.

    Returns:
        A summary with the number of budgets found that cover the project.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return missing_project()
    settings = get_settings()

    inventory, unusable_fixture = _load_fixture(STATE_BUDGETS, tool_context)
    if unusable_fixture is not None:
        return unusable_fixture
    if inventory is None:
        if not settings.billing_account_id:
            return {
                "status": "error",
                "error": "No billing account configured.",
                "hint": "Set CRYPTOJACK_GUARD_BILLING_ACCOUNT to the billing account ID "
                "that funds the project.",
            }
        try:
            client = budgets_v1.BudgetServiceClient()
            budgets = [
                {
                    "name": budget.name,
                    "display_name": budget.display_name,
                    "projects": list(budget.budget_filter.projects),
                    "threshold_percents": [
                        rule.threshold_percent for rule in budget.threshold_rules
                    ],
                    "notifications_configured": bool(
                        budget.notifications_rule.pubsub_topic
                        or budget.notifications_rule.monitoring_notification_channels
                    ),
                }
                for budget in client.list_budgets(
                    request=budgets_v1.ListBudgetsRequest(
                        parent=f"billingAccounts/{settings.billing_account_id}"
                    )
                )
            ]
        except COLLECTION_ERRORS as error:
            return tool_failure(
                tool_context,
                STATE_BUDGETS,
                error,
                "Enable the Billing Budget API and grant the agent "
                "roles/billing.viewer on the billing account.",
            )
        inventory = {
            "project_id": project_id,
            "billing_account": settings.billing_account_id,
            "budgets": budgets,
        }

    record_inventory(tool_context, STATE_BUDGETS, inventory)
    budgets = [b for b in inventory.get("budgets") or [] if isinstance(b, dict)]
    return {
        "status": "ok",
        "project_id": project_id,
        "budget_count": len(budgets),
        "budgets_with_notifications": sum(1 for b in budgets if b.get("notifications_configured")),
    }


def collect_org_policies(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Reads the effective org policy for the constraints that block compute abuse.

    Effective policy is read (not the project's own policy) so inherited folder and
    organisation enforcement counts as protection rather than being reported as a gap.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary listing which of the preventive constraints are enforced.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return missing_project()

    inventory, unusable_fixture = _load_fixture(STATE_ORG_POLICIES, tool_context)
    if unusable_fixture is not None:
        return unusable_fixture
    if inventory is None:
        try:
            client = orgpolicy_v2.OrgPolicyClient()
            constraints = {
                constraint: _effective_constraint(client, project_id, constraint)
                for constraint in sorted(PREVENTIVE_CONSTRAINTS)
            }
        except COLLECTION_ERRORS as error:
            return tool_failure(
                tool_context,
                STATE_ORG_POLICIES,
                error,
                "Enable the Org Policy API and grant the agent roles/orgpolicy.policyViewer.",
            )
        inventory = {"project_id": project_id, "constraints": constraints}

    record_inventory(tool_context, STATE_ORG_POLICIES, inventory)
    constraints = inventory.get("constraints")
    constraints = constraints if isinstance(constraints, dict) else {}
    return {
        "status": "ok",
        "project_id": project_id,
        "enforced": sorted(
            name
            for name, state in constraints.items()
            if isinstance(state, dict) and state.get("enforced")
        ),
        "not_enforced": sorted(
            name
            for name, state in constraints.items()
            if not (isinstance(state, dict) and state.get("enforced"))
        ),
    }


def _effective_constraint(
    client: orgpolicy_v2.OrgPolicyClient, project_id: str, constraint: str
) -> dict[str, Any]:
    """Resolves one constraint to ``{"enforced": bool, "detail": str}``.

    A boolean constraint is enforced when a rule sets ``enforce``; a list constraint
    (``compute.vmExternalIpAccess``) counts as enforced when it denies everything or
    restricts to an explicit allow list rather than allowing all.
    """
    try:
        policy = client.get_effective_policy(
            request=orgpolicy_v2.GetEffectivePolicyRequest(
                name=f"projects/{project_id}/policies/{constraint}"
            )
        )
    except COLLECTION_ERRORS as error:
        return {"enforced": False, "detail": f"could not read: {type(error).__name__}"}

    for rule in policy.spec.rules:
        if rule.enforce:
            return {"enforced": True, "detail": "boolean constraint enforced"}
        if rule.deny_all:
            return {"enforced": True, "detail": "list constraint denies all values"}
        if rule.values.allowed_values and not rule.allow_all:
            return {
                "enforced": True,
                "detail": "list constraint restricted to an allow list",
            }
    return {"enforced": False, "detail": "no enforcing rule in effective policy"}
