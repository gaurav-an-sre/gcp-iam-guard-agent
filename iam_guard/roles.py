"""Knowledge base of GCP roles that matter for IAM abuse paths.

The catalogues below encode publicly documented privilege escalation and lateral
movement primitives. They are intentionally data-only so the rule engine stays
deterministic and reviewable.
"""

from __future__ import annotations

from iam_guard.models import ThreatCategory

# Legacy basic roles. Broad by definition and impossible to scope.
BASIC_ROLES: frozenset[str] = frozenset({"roles/owner", "roles/editor", "roles/viewer"})

# Roles that let a principal grant themselves any other role.
IAM_ADMIN_ROLES: frozenset[str] = frozenset(
    {
        "roles/owner",
        "roles/iam.securityAdmin",
        "roles/iam.organizationRoleAdmin",
        "roles/iam.roleAdmin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/resourcemanager.folderIamAdmin",
        "roles/resourcemanager.organizationAdmin",
    }
)

# Roles whose permissions allow minting credentials for another identity.
IMPERSONATION_ROLES: frozenset[str] = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.workloadIdentityUser",
        "roles/iam.serviceAccountOpenIdTokenCreator",
    }
)

# Roles that allow attaching a service account to a workload the caller controls.
ACTAS_ROLES: frozenset[str] = frozenset(
    {"roles/iam.serviceAccountUser", "roles/editor", "roles/owner"}
)

# Roles that can run attacker supplied code with an attached service account.
# These are the classic "deploy a workload, steal its token" escalation paths and
# are also the roles abused to spin up mining capacity.
COMPUTE_EXECUTION_ROLES: dict[str, str] = {
    "roles/compute.admin": "create GCE instances and attach service accounts",
    "roles/compute.instanceAdmin": "create GCE instances",
    "roles/compute.instanceAdmin.v1": "create GCE instances and set startup scripts",
    "roles/container.admin": "create GKE clusters and node pools",
    "roles/container.clusterAdmin": "create GKE clusters and node pools",
    "roles/dataproc.editor": "create Dataproc clusters",
    "roles/dataflow.developer": "launch Dataflow jobs",
    "roles/run.admin": "deploy Cloud Run services",
    "roles/run.developer": "deploy Cloud Run services",
    "roles/cloudfunctions.admin": "deploy Cloud Functions",
    "roles/cloudfunctions.developer": "deploy Cloud Functions",
    "roles/cloudbuild.builds.editor": "run arbitrary Cloud Build steps",
    "roles/composer.admin": "run Airflow DAGs",
    "roles/notebooks.admin": "create Vertex AI notebook runtimes",
    "roles/aiplatform.admin": "create Vertex AI custom training jobs",
    "roles/deploymentmanager.editor": "apply Deployment Manager templates",
    "roles/appengine.deployer": "deploy App Engine versions",
}

# Roles that let an attacker turn on the APIs and quota needed for mining.
QUOTA_AND_BILLING_ROLES: frozenset[str] = frozenset(
    {
        "roles/serviceusage.serviceUsageAdmin",
        "roles/billing.admin",
        "roles/billing.projectManager",
        "roles/owner",
    }
)

# Roles granting bulk read of data at rest.
DATA_READ_ROLES: frozenset[str] = frozenset(
    {
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectViewer",
        "roles/storage.legacyBucketOwner",
        "roles/storage.legacyObjectReader",
        "roles/bigquery.dataOwner",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataViewer",
        "roles/bigquery.admin",
        "roles/viewer",
        "roles/editor",
        "roles/owner",
    }
)

# Roles that hide an attacker's tracks once inside.
LOG_TAMPERING_ROLES: frozenset[str] = frozenset(
    {
        "roles/logging.admin",
        "roles/logging.configWriter",
        "roles/logging.privateLogViewer",
        "roles/owner",
    }
)

CATEGORY_BY_ROLE_GROUP: dict[str, ThreatCategory] = {
    "iam_admin": ThreatCategory.PRIVILEGE_ESCALATION,
    "impersonation": ThreatCategory.PHISHING_TAKEOVER,
    "compute_execution": ThreatCategory.CRYPTOJACKING,
    "data_read": ThreatCategory.DATA_EXFILTRATION,
}


def is_service_account(principal: str) -> bool:
    return principal.startswith("serviceAccount:")


def is_public(principal: str) -> bool:
    return principal in {"allUsers", "allAuthenticatedUsers"}


def principal_domain(principal: str) -> str:
    """Returns the lower-cased domain of ``user:``/``group:``/``domain:`` principals."""
    if principal.startswith("domain:"):
        return principal.split(":", 1)[1].lower()
    if "@" in principal:
        return principal.rsplit("@", 1)[1].lower()
    return ""


def role_short_name(role: str) -> str:
    return role.split("/")[-1]
