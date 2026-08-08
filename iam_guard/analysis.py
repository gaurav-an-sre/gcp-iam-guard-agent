"""Deterministic IAM rule engine.

The engine consumes the raw inventory gathered by the collector tools and emits
:class:`~iam_guard.models.Finding` objects. It performs no network calls and no
model calls, so its output is reproducible and unit testable. The LLM stages of
the workflow only explain and prioritise what this module detects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from iam_guard import roles as role_kb
from iam_guard.config import Settings, get_settings
from iam_guard.models import (
    STATE_BIGQUERY,
    STATE_GCE,
    STATE_GCS,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
    Finding,
    Severity,
    ThreatCategory,
    sort_findings,
)
from iam_guard.normalize import dicts as _dicts
from iam_guard.normalize import mapping as _mapping
from iam_guard.normalize import strings as _strings
from iam_guard.normalize import text as _text

_PUBLIC_BQ_ENTITIES = {"allAuthenticatedUsers", "allUsers"}


def _bindings(project_iam: dict[str, Any]) -> list[dict[str, Any]]:
    return _dicts(project_iam, "bindings")


def _members(binding: dict[str, Any]) -> list[str]:
    return _strings(binding, "members")


def _principal_roles(project_iam: dict[str, Any]) -> dict[str, set[str]]:
    """Inverts the project policy into ``principal -> {roles}``."""
    mapping: dict[str, set[str]] = {}
    for binding in _bindings(project_iam):
        role = _text(binding, "role")
        for member in _members(binding):
            mapping.setdefault(member, set()).add(role)
    return mapping


def _is_untrusted(principal: str, settings: Settings) -> bool:
    domain = role_kb.principal_domain(principal)
    if not domain:
        return False
    if domain in settings.untrusted_domains:
        return True
    return bool(settings.trusted_domains) and domain not in settings.trusted_domains


def _project_ref(project_iam: dict[str, Any]) -> str:
    project_id = _text(project_iam, "project_id", "unknown-project")
    return f"//cloudresourcemanager.googleapis.com/projects/{project_id}"


# --------------------------------------------------------------------------- #
# Project level IAM policy rules
# --------------------------------------------------------------------------- #


def check_project_iam(project_iam: dict[str, Any], settings: Settings) -> list[Finding]:
    findings: list[Finding] = []
    project_id = _text(project_iam, "project_id", "unknown-project")
    resource = _project_ref(project_iam)

    for binding in _bindings(project_iam):
        role = _text(binding, "role")
        condition = binding.get("condition")
        members = _members(binding)

        public_members = [m for m in members if role_kb.is_public(m)]
        if public_members:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-PUBLIC-BINDING",
                    title=f"Project-wide {role} granted to the public",
                    severity=Severity.CRITICAL,
                    categories=[
                        ThreatCategory.PUBLIC_EXPOSURE,
                        ThreatCategory.PRIVILEGE_ESCALATION,
                    ],
                    service="iam",
                    resource=resource,
                    principals=public_members,
                    roles=[role],
                    evidence={"binding": binding},
                    explanation=(
                        "Anyone on the internet inherits this role on every resource in "
                        "the project. This is the single fastest path to cryptojacking "
                        "and data theft."
                    ),
                    remediation=f"Remove {public_members} from {role} on project {project_id}.",
                    remediation_commands=[
                        f"gcloud projects remove-iam-policy-binding {project_id} "
                        f'--member="{member}" --role="{role}"'
                        for member in public_members
                    ],
                )
            )

        human_members = [m for m in members if m.startswith(("user:", "group:", "domain:"))]

        if role in role_kb.BASIC_ROLES and role != "roles/viewer" and members:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-BASIC-ROLE",
                    title=f"Legacy basic role {role} still in use",
                    severity=Severity.HIGH if role == "roles/owner" else Severity.MEDIUM,
                    categories=[ThreatCategory.PRIVILEGE_ESCALATION],
                    service="iam",
                    resource=resource,
                    principals=members,
                    roles=[role],
                    evidence={"member_count": len(members)},
                    explanation=(
                        "Basic roles bundle thousands of permissions, including the "
                        "ability to create workloads and impersonate service accounts. "
                        "They cannot be scoped down."
                    ),
                    remediation=(
                        f"Replace {role} with the least-privilege predefined roles each "
                        "principal actually needs."
                    ),
                    remediation_commands=[
                        f"gcloud projects get-iam-policy {project_id} --format=json"
                    ],
                )
            )

        if role in role_kb.IAM_ADMIN_ROLES and not condition:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-UNCONDITIONAL-IAM-ADMIN",
                    title=f"{role} granted without an IAM condition",
                    severity=Severity.HIGH,
                    categories=[ThreatCategory.PRIVILEGE_ESCALATION],
                    service="iam",
                    resource=resource,
                    principals=members,
                    roles=[role],
                    evidence={"condition": None},
                    explanation=(
                        "Holders of this role can grant themselves any other role, so a "
                        "single phished session becomes permanent project ownership."
                    ),
                    remediation=(
                        "Move these grants behind an IAM condition (time-bound or "
                        "resource-scoped) or into a PAM entitlement that requires "
                        "just-in-time approval."
                    ),
                )
            )

        if role in role_kb.IMPERSONATION_ROLES and members:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-BROAD-IMPERSONATION",
                    title=f"{role} granted at project scope",
                    severity=Severity.HIGH,
                    categories=[
                        ThreatCategory.PHISHING_TAKEOVER,
                        ThreatCategory.PRIVILEGE_ESCALATION,
                    ],
                    service="iam",
                    resource=resource,
                    principals=members,
                    roles=[role],
                    evidence={"scope": "project"},
                    explanation=(
                        "Granted on the project, this role applies to every current and "
                        "future service account, letting an attacker mint tokens for the "
                        "most privileged identity in the project."
                    ),
                    remediation=(
                        "Grant impersonation roles on the individual service account "
                        "resource instead of the project."
                    ),
                    remediation_commands=[
                        f"gcloud projects remove-iam-policy-binding {project_id} "
                        f'--member="{member}" --role="{role}"'
                        for member in members
                    ],
                )
            )

        untrusted = [m for m in human_members if _is_untrusted(m, settings)]
        if untrusted:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-EXTERNAL-PRINCIPAL",
                    title=f"External or consumer account holds {role}",
                    severity=Severity.HIGH
                    if role in role_kb.IAM_ADMIN_ROLES | role_kb.BASIC_ROLES
                    else Severity.MEDIUM,
                    categories=[ThreatCategory.PHISHING_TAKEOVER],
                    service="iam",
                    resource=resource,
                    principals=untrusted,
                    roles=[role],
                    evidence={"trusted_domains": list(settings.trusted_domains)},
                    explanation=(
                        "Accounts outside the organisation are not covered by its 2SV, "
                        "session-length and device policies, so they are the preferred "
                        "phishing target for reaching this project."
                    ),
                    remediation=(
                        "Remove the consumer accounts and re-grant access to managed "
                        "identities, then enforce the Domain Restricted Sharing "
                        "organisation policy."
                    ),
                    remediation_commands=[
                        f"gcloud projects remove-iam-policy-binding {project_id} "
                        f'--member="{member}" --role="{role}"'
                        for member in untrusted
                    ],
                )
            )

        quota_roles = role_kb.QUOTA_AND_BILLING_ROLES & {role}
        if quota_roles and human_members:
            findings.append(
                Finding(
                    rule_id="IAM-PROJ-QUOTA-CONTROL",
                    title=f"{role} allows raising quota and enabling new APIs",
                    severity=Severity.MEDIUM,
                    categories=[ThreatCategory.CRYPTOJACKING],
                    service="iam",
                    resource=resource,
                    principals=human_members,
                    roles=[role],
                    evidence={},
                    explanation=(
                        "Mining campaigns start by enabling Compute or GKE APIs and "
                        "raising CPU/GPU quota. This role removes that speed bump."
                    ),
                    remediation=(
                        "Restrict quota and billing administration to a small break-glass "
                        "group and alert on serviceusage.services.enable in audit logs."
                    ),
                )
            )

    if not project_iam.get("audit_configs"):
        findings.append(
            Finding(
                rule_id="IAM-PROJ-NO-DATA-ACCESS-LOGS",
                title="Data access audit logs are not configured",
                severity=Severity.MEDIUM,
                categories=[ThreatCategory.WEAK_HYGIENE],
                service="iam",
                resource=resource,
                explanation=(
                    "Without DATA_READ/DATA_WRITE audit logs there is no record of who "
                    "read Cloud Storage objects or BigQuery tables, so exfiltration "
                    "after a phishing incident cannot be scoped."
                ),
                remediation=(
                    "Enable DATA_READ and DATA_WRITE audit logs for storage.googleapis.com "
                    "and bigquery.googleapis.com in the project IAM policy."
                ),
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# Cross-resource attack path correlation
# --------------------------------------------------------------------------- #


def check_attack_paths(
    project_iam: dict[str, Any],
    service_accounts: dict[str, Any],
    settings: Settings,
) -> list[Finding]:
    """Correlates individually-acceptable grants into concrete abuse chains."""
    findings: list[Finding] = []
    resource = _project_ref(project_iam)
    project_id = _text(project_iam, "project_id", "unknown-project")
    granted = _principal_roles(project_iam)

    privileged_sas = [
        _text(sa, "email")
        for sa in _dicts(service_accounts, "service_accounts")
        if granted.get(f"serviceAccount:{_text(sa, 'email')}", set())
        & (role_kb.IAM_ADMIN_ROLES | role_kb.BASIC_ROLES - {"roles/viewer"})
    ]

    for principal, principal_roles in granted.items():
        actas = principal_roles & role_kb.ACTAS_ROLES
        execution = {role for role in principal_roles if role in role_kb.COMPUTE_EXECUTION_ROLES}
        if not (actas and execution):
            continue

        primitives = sorted(role_kb.COMPUTE_EXECUTION_ROLES[role] for role in execution)
        severity = Severity.CRITICAL if privileged_sas else Severity.HIGH
        findings.append(
            Finding(
                rule_id="IAM-PATH-ACTAS-ESCALATION",
                title=f"{principal} can escalate by attaching a service account to a workload",
                severity=severity,
                categories=[
                    ThreatCategory.PRIVILEGE_ESCALATION,
                    ThreatCategory.CRYPTOJACKING,
                ],
                service="iam",
                resource=resource,
                principals=[principal],
                roles=sorted(actas | execution),
                evidence={
                    "actAs_roles": sorted(actas),
                    "execution_primitives": primitives,
                    "reachable_privileged_service_accounts": privileged_sas,
                },
                explanation=(
                    "Combining actAs with the ability to run code means the principal can "
                    "deploy a workload, attach a more privileged service account and read "
                    "its access token from the metadata server. The same primitive is what "
                    "cryptojackers use to launch mining fleets."
                ),
                remediation=(
                    "Split the two capabilities across different principals, or scope "
                    "roles/iam.serviceAccountUser to a single low-privilege runtime "
                    "service account."
                ),
                remediation_commands=[
                    f"gcloud projects remove-iam-policy-binding {project_id} "
                    f'--member="{principal}" --role="roles/iam.serviceAccountUser"'
                ],
            )
        )

    for principal, principal_roles in granted.items():
        if (
            principal_roles & role_kb.IMPERSONATION_ROLES
            and principal_roles & role_kb.DATA_READ_ROLES
        ):
            findings.append(
                Finding(
                    rule_id="IAM-PATH-IMPERSONATION-TO-DATA",
                    title=f"{principal} can impersonate identities and read project data",
                    severity=Severity.HIGH,
                    categories=[
                        ThreatCategory.DATA_EXFILTRATION,
                        ThreatCategory.PHISHING_TAKEOVER,
                    ],
                    service="iam",
                    resource=resource,
                    principals=[principal],
                    roles=sorted(
                        principal_roles & (role_kb.IMPERSONATION_ROLES | role_kb.DATA_READ_ROLES)
                    ),
                    evidence={},
                    explanation=(
                        "A phished session for this principal yields both long-lived "
                        "credentials for other identities and bulk data read, which is the "
                        "full exfiltration chain in one account."
                    ),
                    remediation=(
                        "Separate credential-minting from data access and require "
                        "just-in-time elevation for the impersonation role."
                    ),
                )
            )

    return findings


# --------------------------------------------------------------------------- #
# Service accounts and keys
# --------------------------------------------------------------------------- #


def check_service_accounts(
    service_accounts: dict[str, Any],
    project_iam: dict[str, Any],
    settings: Settings,
) -> list[Finding]:
    findings: list[Finding] = []
    granted = _principal_roles(project_iam)

    for account in _dicts(service_accounts, "service_accounts"):
        email = _text(account, "email")
        resource = f"//iam.googleapis.com/projects/-/serviceAccounts/{email}"
        keys = _dicts(account, "user_managed_keys")
        if keys:
            findings.append(
                Finding(
                    rule_id="IAM-SA-USER-MANAGED-KEY",
                    title=f"Service account {email} has user-managed keys",
                    severity=Severity.HIGH,
                    categories=[
                        ThreatCategory.PHISHING_TAKEOVER,
                        ThreatCategory.PRIVILEGE_ESCALATION,
                    ],
                    service="iam",
                    resource=resource,
                    principals=[f"serviceAccount:{email}"],
                    evidence={"key_count": len(keys), "keys": keys},
                    explanation=(
                        "Exported JSON keys never expire, are commonly leaked through "
                        "phishing, repositories and CI logs, and grant the service "
                        "account's full authority from anywhere on the internet."
                    ),
                    remediation=(
                        "Delete the keys and switch callers to Workload Identity "
                        "Federation or attached service accounts."
                    ),
                    remediation_commands=[
                        f"gcloud iam service-accounts keys delete {key.get('key_id', 'KEY_ID')} "
                        f"--iam-account={email}"
                        for key in keys
                    ],
                )
            )

        if account.get("disabled") and granted.get(f"serviceAccount:{email}"):
            findings.append(
                Finding(
                    rule_id="IAM-SA-DISABLED-WITH-ROLES",
                    title=f"Disabled service account {email} still holds project roles",
                    severity=Severity.LOW,
                    categories=[ThreatCategory.WEAK_HYGIENE],
                    service="iam",
                    resource=resource,
                    principals=[f"serviceAccount:{email}"],
                    roles=sorted(granted[f"serviceAccount:{email}"]),
                    evidence={},
                    explanation=(
                        "Re-enabling the account instantly restores its access, and stale "
                        "bindings hide the real permission surface during review."
                    ),
                    remediation="Delete the service account and its bindings.",
                )
            )

        for binding in _dicts(account, "iam_policy_bindings"):
            role = _text(binding, "role")
            members = _members(binding)
            public = [m for m in members if role_kb.is_public(m)]
            if public:
                findings.append(
                    Finding(
                        rule_id="IAM-SA-PUBLIC-IMPERSONATION",
                        title=f"Anyone can impersonate {email}",
                        severity=Severity.CRITICAL,
                        categories=[
                            ThreatCategory.PUBLIC_EXPOSURE,
                            ThreatCategory.PRIVILEGE_ESCALATION,
                        ],
                        service="iam",
                        resource=resource,
                        principals=public,
                        roles=[role],
                        evidence={"binding": binding},
                        explanation=(
                            "A public impersonation binding hands the service account's "
                            "permissions to the entire internet."
                        ),
                        remediation=f"Remove {public} from {role} on {email}.",
                        remediation_commands=[
                            f"gcloud iam service-accounts remove-iam-policy-binding {email} "
                            f'--member="{member}" --role="{role}"'
                            for member in public
                        ],
                    )
                )

            untrusted = [
                m
                for m in members
                if m.startswith(("user:", "group:", "domain:")) and _is_untrusted(m, settings)
            ]
            if untrusted and role in role_kb.IMPERSONATION_ROLES:
                findings.append(
                    Finding(
                        rule_id="IAM-SA-EXTERNAL-IMPERSONATION",
                        title=f"External principal can impersonate {email}",
                        severity=Severity.HIGH,
                        categories=[ThreatCategory.PHISHING_TAKEOVER],
                        service="iam",
                        resource=resource,
                        principals=untrusted,
                        roles=[role],
                        evidence={},
                        explanation=(
                            "Impersonation from an unmanaged account turns a phished "
                            "consumer mailbox into workload-level access."
                        ),
                        remediation=(
                            "Remove the binding and use a managed group with Workload "
                            "Identity Federation for external automation."
                        ),
                    )
                )

    return findings


# --------------------------------------------------------------------------- #
# Compute Engine
# --------------------------------------------------------------------------- #


def check_gce(gce: dict[str, Any], project_iam: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    granted = _principal_roles(project_iam)
    project_metadata = _mapping(gce, "project_metadata")

    if str(project_metadata.get("enable-oslogin", "")).upper() not in {"TRUE", "1"}:
        findings.append(
            Finding(
                rule_id="GCE-OSLOGIN-DISABLED",
                title="OS Login is not enforced at project level",
                severity=Severity.MEDIUM,
                categories=[ThreatCategory.WEAK_HYGIENE, ThreatCategory.PHISHING_TAKEOVER],
                service="gce",
                resource=f"//compute.googleapis.com/projects/{gce.get('project_id', 'unknown')}",
                evidence={"enable-oslogin": project_metadata.get("enable-oslogin")},
                explanation=(
                    "Without OS Login, SSH access is governed by metadata keys rather "
                    "than IAM, so revoking a compromised user in IAM does not revoke "
                    "their shell access."
                ),
                remediation="Set the project metadata enable-oslogin=TRUE.",
                remediation_commands=[
                    f"gcloud compute project-info add-metadata "
                    f"--project={gce.get('project_id', 'PROJECT_ID')} "
                    "--metadata enable-oslogin=TRUE"
                ],
            )
        )

    for instance in _dicts(gce, "instances"):
        name = _text(instance, "name")
        zone = _text(instance, "zone")
        project = _text(gce, "project_id")
        resource = f"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}"
        attached = _dicts(instance, "service_accounts")

        for sa in attached:
            email = _text(sa, "email")
            scopes = _strings(sa, "scopes")
            is_default = email.endswith("-compute@developer.gserviceaccount.com")
            broad_scope = "https://www.googleapis.com/auth/cloud-platform" in scopes
            sa_roles = granted.get(f"serviceAccount:{email}", set())
            dangerous_roles = sorted(
                sa_roles & (role_kb.IAM_ADMIN_ROLES | role_kb.BASIC_ROLES - {"roles/viewer"})
            )

            if is_default and broad_scope:
                findings.append(
                    Finding(
                        rule_id="GCE-DEFAULT-SA-FULL-SCOPE",
                        title=(
                            f"Instance {name} runs as the default service account "
                            "with cloud-platform scope"
                        ),
                        severity=Severity.HIGH,
                        categories=[
                            ThreatCategory.PRIVILEGE_ESCALATION,
                            ThreatCategory.DATA_EXFILTRATION,
                        ],
                        service="gce",
                        resource=resource,
                        principals=[f"serviceAccount:{email}"],
                        roles=dangerous_roles,
                        evidence={"scopes": scopes},
                        explanation=(
                            "Any code or SSRF bug on this VM can read a cloud-platform "
                            "token from the metadata server. The default compute service "
                            "account is usually still a project Editor."
                        ),
                        remediation=(
                            "Attach a dedicated least-privilege service account and drop "
                            "the cloud-platform scope."
                        ),
                        remediation_commands=[
                            f"gcloud compute instances set-service-account {name} "
                            f"--zone={zone} --service-account=NEW_SA_EMAIL "
                            "--scopes=https://www.googleapis.com/auth/devstorage.read_only"
                        ],
                    )
                )
            elif dangerous_roles:
                findings.append(
                    Finding(
                        rule_id="GCE-PRIVILEGED-SA-ATTACHED",
                        title=f"Instance {name} runs as a highly privileged service account",
                        severity=Severity.HIGH,
                        categories=[ThreatCategory.PRIVILEGE_ESCALATION],
                        service="gce",
                        resource=resource,
                        principals=[f"serviceAccount:{email}"],
                        roles=dangerous_roles,
                        evidence={"scopes": scopes},
                        explanation=(
                            "Compromising this VM is equivalent to compromising the "
                            "project, because the attached identity can administer IAM."
                        ),
                        remediation="Re-attach a service account scoped to the workload's needs.",
                    )
                )

        if instance.get("external_ips") and instance.get("status") == "RUNNING":
            severity = Severity.HIGH if attached else Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id="GCE-EXTERNAL-IP",
                    title=f"Instance {name} is directly reachable from the internet",
                    severity=severity,
                    categories=[ThreatCategory.PUBLIC_EXPOSURE, ThreatCategory.CRYPTOJACKING],
                    service="gce",
                    resource=resource,
                    evidence={"external_ips": instance.get("external_ips")},
                    explanation=(
                        "Internet-facing VMs with an attached service account are the "
                        "most common cryptojacking entry point: exploit the workload, "
                        "steal the metadata token, then launch mining instances."
                    ),
                    remediation=(
                        "Remove the external IP and front the workload with a load "
                        "balancer or IAP TCP forwarding."
                    ),
                    remediation_commands=[
                        f"gcloud compute instances delete-access-config {name} --zone={zone}"
                    ],
                )
            )

        metadata = _mapping(instance, "metadata")
        startup_script = metadata.get("startup-script") or metadata.get("startup-script-url")
        if startup_script and instance.get("block_project_ssh_keys") is False:
            findings.append(
                Finding(
                    rule_id="GCE-PROJECT-SSH-KEYS-ALLOWED",
                    title=f"Instance {name} accepts project-wide SSH keys",
                    severity=Severity.MEDIUM,
                    categories=[ThreatCategory.WEAK_HYGIENE],
                    service="gce",
                    resource=resource,
                    evidence={"block_project_ssh_keys": False},
                    explanation=(
                        "Any principal who can edit project metadata gains shell access "
                        "to this VM without an instance-level IAM grant."
                    ),
                    remediation="Set the instance metadata block-project-ssh-keys=TRUE.",
                    remediation_commands=[
                        f"gcloud compute instances add-metadata {name} --zone={zone} "
                        "--metadata block-project-ssh-keys=TRUE"
                    ],
                )
            )

        if instance.get("serial_port_enabled"):
            findings.append(
                Finding(
                    rule_id="GCE-SERIAL-PORT-ENABLED",
                    title=f"Interactive serial console is enabled on {name}",
                    severity=Severity.MEDIUM,
                    categories=[ThreatCategory.WEAK_HYGIENE],
                    service="gce",
                    resource=resource,
                    evidence={},
                    explanation=(
                        "The serial console bypasses firewall rules and OS Login, giving "
                        "anyone with compute.instances.setMetadata a side channel in."
                    ),
                    remediation="Disable serial-port-enable in the instance metadata.",
                    remediation_commands=[
                        f"gcloud compute instances add-metadata {name} --zone={zone} "
                        "--metadata serial-port-enable=FALSE"
                    ],
                )
            )

        if instance.get("gpu_count", 0) and instance.get("status") == "RUNNING":
            findings.append(
                Finding(
                    rule_id="GCE-GPU-WORKLOAD-REVIEW",
                    title=f"GPU instance {name} should be confirmed as expected capacity",
                    severity=Severity.LOW,
                    categories=[ThreatCategory.CRYPTOJACKING],
                    service="gce",
                    resource=resource,
                    evidence={
                        "gpu_count": instance.get("gpu_count"),
                        "machine_type": instance.get("machine_type"),
                    },
                    explanation=(
                        "GPU and high-CPU instances are what mining campaigns create. "
                        "Confirm this instance is intentional and covered by a budget alert."
                    ),
                    remediation=(
                        "Verify the owner of this workload and constrain machine types "
                        "with the constraints/compute.vmExternalIpAccess and custom "
                        "machine-family organisation policies."
                    ),
                )
            )

    return findings


# --------------------------------------------------------------------------- #
# Cloud Storage
# --------------------------------------------------------------------------- #


def check_gcs(gcs: dict[str, Any], settings: Settings) -> list[Finding]:
    findings: list[Finding] = []

    for bucket in _dicts(gcs, "buckets"):
        name = _text(bucket, "name")
        resource = f"//storage.googleapis.com/projects/_/buckets/{name}"

        for binding in _dicts(bucket, "bindings"):
            role = _text(binding, "role")
            members = _members(binding)
            public = [m for m in members if role_kb.is_public(m)]
            if public:
                findings.append(
                    Finding(
                        rule_id="GCS-PUBLIC-BUCKET",
                        title=f"Bucket {name} is publicly accessible",
                        severity=Severity.CRITICAL,
                        categories=[
                            ThreatCategory.PUBLIC_EXPOSURE,
                            ThreatCategory.DATA_EXFILTRATION,
                        ],
                        service="gcs",
                        resource=resource,
                        principals=public,
                        roles=[role],
                        evidence={"binding": binding},
                        explanation=(
                            "Public buckets leak data and, when writable, let attackers "
                            "plant malicious payloads that your own workloads execute."
                        ),
                        remediation=f"Remove {public} from {role} on gs://{name}.",
                        remediation_commands=[
                            f"gcloud storage buckets remove-iam-policy-binding gs://{name} "
                            f'--member="{member}" --role="{role}"'
                            for member in public
                        ],
                    )
                )

            if role in {"roles/storage.admin", "roles/storage.objectAdmin"} and members:
                untrusted = [m for m in members if _is_untrusted(m, settings)]
                if untrusted:
                    findings.append(
                        Finding(
                            rule_id="GCS-EXTERNAL-WRITE-ACCESS",
                            title=f"External principal can write to bucket {name}",
                            severity=Severity.HIGH,
                            categories=[
                                ThreatCategory.PHISHING_TAKEOVER,
                                ThreatCategory.DATA_EXFILTRATION,
                            ],
                            service="gcs",
                            resource=resource,
                            principals=untrusted,
                            roles=[role],
                            evidence={},
                            explanation=(
                                "Write access from an unmanaged account allows supply "
                                "chain style tampering of the artefacts this project reads."
                            ),
                            remediation="Restrict write access to managed service accounts.",
                        )
                    )

            if role.startswith("roles/storage.legacy") and members:
                findings.append(
                    Finding(
                        rule_id="GCS-LEGACY-ROLE",
                        title=f"Legacy ACL-backed role {role} on bucket {name}",
                        severity=Severity.LOW,
                        categories=[ThreatCategory.WEAK_HYGIENE],
                        service="gcs",
                        resource=resource,
                        principals=members,
                        roles=[role],
                        evidence={},
                        explanation=(
                            "Legacy roles come from ACLs, are invisible to most IAM "
                            "reviews and often outlive the person who granted them."
                        ),
                        remediation="Migrate to uniform bucket-level access and modern roles.",
                    )
                )

        if not bucket.get("uniform_bucket_level_access"):
            findings.append(
                Finding(
                    rule_id="GCS-UBLA-DISABLED",
                    title=f"Uniform bucket-level access is disabled on {name}",
                    severity=Severity.MEDIUM,
                    categories=[ThreatCategory.WEAK_HYGIENE, ThreatCategory.PUBLIC_EXPOSURE],
                    service="gcs",
                    resource=resource,
                    evidence={},
                    explanation=(
                        "Object ACLs can make individual objects public even when the "
                        "bucket IAM policy looks clean, so IAM review alone is unreliable."
                    ),
                    remediation="Enable uniform bucket-level access.",
                    remediation_commands=[
                        f"gcloud storage buckets update gs://{name} --uniform-bucket-level-access"
                    ],
                )
            )

        if bucket.get("public_access_prevention") != "enforced":
            findings.append(
                Finding(
                    rule_id="GCS-PAP-NOT-ENFORCED",
                    title=f"Public access prevention is not enforced on {name}",
                    severity=Severity.MEDIUM,
                    categories=[ThreatCategory.PUBLIC_EXPOSURE],
                    service="gcs",
                    resource=resource,
                    evidence={"public_access_prevention": bucket.get("public_access_prevention")},
                    explanation=(
                        "Without enforcement, one mistaken allUsers binding immediately "
                        "exposes the bucket to the internet."
                    ),
                    remediation="Enforce public access prevention on the bucket or organisation.",
                    remediation_commands=[
                        f"gcloud storage buckets update gs://{name} --public-access-prevention"
                    ],
                )
            )

    return findings


# --------------------------------------------------------------------------- #
# BigQuery
# --------------------------------------------------------------------------- #


def check_bigquery(bigquery_inventory: dict[str, Any], settings: Settings) -> list[Finding]:
    findings: list[Finding] = []
    project_id = _text(bigquery_inventory, "project_id", "unknown-project")

    for dataset in _dicts(bigquery_inventory, "datasets"):
        dataset_id = _text(dataset, "dataset_id")
        resource = f"//bigquery.googleapis.com/projects/{project_id}/datasets/{dataset_id}"

        for entry in _dicts(dataset, "access_entries"):
            entity_type = _text(entry, "entity_type")
            entity_id = _text(entry, "entity_id")
            role = _text(entry, "role", "READER")

            if entity_type == "specialGroup" and entity_id in _PUBLIC_BQ_ENTITIES:
                findings.append(
                    Finding(
                        rule_id="BQ-PUBLIC-DATASET",
                        title=f"Dataset {dataset_id} is shared with {entity_id}",
                        severity=Severity.CRITICAL,
                        categories=[
                            ThreatCategory.PUBLIC_EXPOSURE,
                            ThreatCategory.DATA_EXFILTRATION,
                        ],
                        service="bigquery",
                        resource=resource,
                        principals=[entity_id],
                        roles=[role],
                        evidence={"access_entry": entry},
                        explanation=(
                            "Every Google account can query this dataset, and query costs "
                            "are billed to your project."
                        ),
                        remediation=f"Remove the {entity_id} access entry from {dataset_id}.",
                        remediation_commands=[
                            f"bq show --format=prettyjson {project_id}:{dataset_id} > dataset.json "
                            "# edit access list, then: "
                            f"bq update --source dataset.json {project_id}:{dataset_id}"
                        ],
                    )
                )

            if entity_type == "specialGroup" and entity_id == "projectEditors" and role == "OWNER":
                findings.append(
                    Finding(
                        rule_id="BQ-PROJECT-EDITORS-OWNER",
                        title=f"All project editors own dataset {dataset_id}",
                        severity=Severity.MEDIUM,
                        categories=[ThreatCategory.PRIVILEGE_ESCALATION],
                        service="bigquery",
                        resource=resource,
                        principals=["projectEditors"],
                        roles=[role],
                        evidence={},
                        explanation=(
                            "Dataset ownership follows the broad Editor role, so anyone "
                            "who escalates to Editor can also delete or exfiltrate data."
                        ),
                        remediation=(
                            "Grant dataset roles to named groups instead of projectEditors."
                        ),
                    )
                )

            if entity_type == "domain":
                is_untrusted_domain = (
                    entity_id.lower() in settings.untrusted_domains
                    or bool(settings.trusted_domains)
                    and entity_id.lower() not in settings.trusted_domains
                )
                findings.append(
                    Finding(
                        rule_id="BQ-DOMAIN-WIDE-ACCESS",
                        title=f"Dataset {dataset_id} is shared with the whole domain {entity_id}",
                        severity=Severity.HIGH if is_untrusted_domain else Severity.MEDIUM,
                        categories=[ThreatCategory.DATA_EXFILTRATION],
                        service="bigquery",
                        resource=resource,
                        principals=[f"domain:{entity_id}"],
                        roles=[role],
                        evidence={},
                        explanation=(
                            "Domain-wide sharing means every phished mailbox in that "
                            "domain is a data breach of this dataset."
                        ),
                        remediation="Replace domain sharing with specific groups.",
                    )
                )

            if entity_type == "userByEmail" and _is_untrusted(f"user:{entity_id}", settings):
                findings.append(
                    Finding(
                        rule_id="BQ-EXTERNAL-USER-ACCESS",
                        title=f"External account {entity_id} has {role} on {dataset_id}",
                        severity=Severity.HIGH,
                        categories=[
                            ThreatCategory.DATA_EXFILTRATION,
                            ThreatCategory.PHISHING_TAKEOVER,
                        ],
                        service="bigquery",
                        resource=resource,
                        principals=[f"user:{entity_id}"],
                        roles=[role],
                        evidence={},
                        explanation=(
                            "Consumer accounts are outside your 2SV and session controls, "
                            "so their access to warehouse data is high risk."
                        ),
                        remediation="Remove the account and use a managed identity.",
                    )
                )

    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def analyze(inventory: dict[str, Any], settings: Settings | None = None) -> list[Finding]:
    """Runs every rule over ``inventory`` and returns findings ordered by severity."""
    settings = settings or get_settings()
    project_iam = _mapping(inventory, STATE_PROJECT_IAM)
    service_accounts = _mapping(inventory, STATE_SERVICE_ACCOUNTS)
    gce = _mapping(inventory, STATE_GCE)
    gcs = _mapping(inventory, STATE_GCS)
    bigquery_inventory = _mapping(inventory, STATE_BIGQUERY)

    findings: list[Finding] = []
    if project_iam:
        findings += check_project_iam(project_iam, settings)
        findings += check_attack_paths(project_iam, service_accounts, settings)
    if service_accounts:
        findings += check_service_accounts(service_accounts, project_iam, settings)
    if gce:
        findings += check_gce(gce, project_iam)
    if gcs:
        findings += check_gcs(gcs, settings)
    if bigquery_inventory:
        findings += check_bigquery(bigquery_inventory, settings)

    return sort_findings(_dedupe(findings))


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.resource,
            tuple(sorted(finding.principals)),
            tuple(sorted(finding.roles)),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
