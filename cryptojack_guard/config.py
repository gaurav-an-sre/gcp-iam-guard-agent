"""Runtime configuration for the Cryptojack Guard agent.

Every detection threshold lives here rather than inline in the rule engine, because
"suspicious" is workload specific: a rendering farm legitimately pins CPU for hours,
a batch ML project legitimately holds GPU quota. Operators tune these instead of
patching rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "gemini-2.5-flash"

#: Fixture env var, mirroring ``IAM_GUARD_FIXTURE``.
FIXTURE_ENV_VAR = "CRYPTOJACK_GUARD_FIXTURE"

#: Substrings that mark an SCC finding category as cryptomining specific. SCC category
#: names are stable strings such as ``Execution: Cryptocurrency Mining Hash Match`` and
#: ``Malware: Cryptomining Bad Domain``.
MINING_CATEGORY_MARKERS: tuple[str, ...] = (
    "cryptocurrency mining",
    "cryptomining",
    "crypto mining",
    "coinmining",
)

#: Org policy constraints that materially raise the cost of hijacking a project for
#: mining. Each one is reported as a preventive gap when it is not enforced.
PREVENTIVE_CONSTRAINTS: dict[str, str] = {
    "constraints/iam.disableServiceAccountKeyCreation": (
        "Exported service-account keys are the most common cryptojacking entry point: "
        "they leak into repos and CI logs and never expire."
    ),
    "constraints/compute.vmExternalIpAccess": (
        "Miners need outbound reachability to a pool and operators need inbound access; "
        "denying external IPs by default forces traffic through inspected egress."
    ),
    "constraints/compute.requireOsLogin": (
        "OS Login ties SSH to IAM identities and audit logs, removing metadata SSH keys "
        "as a persistence mechanism."
    ),
    "constraints/compute.disableSerialPortAccess": (
        "Interactive serial console access is an out-of-band way to run a miner that "
        "bypasses SSH controls and OS Login."
    ),
    "constraints/compute.disableNestedVirtualization": (
        "Nested virtualization lets an attacker hide a mining workload inside a nested "
        "VM where host-level agents cannot see it."
    ),
}


@dataclass(frozen=True)
class Settings:
    """Settings resolved from the environment.

    Attributes:
        model: Gemini model used by the scope and report stages.
        default_project_id: Project analysed when the user does not name one.
        organization_id: Numeric org ID, needed to read SCC findings and org policy.
        billing_account_id: Billing account whose budgets cover the project.
        cpu_threshold: Mean CPU fraction (0-1) above which a VM looks compute pinned.
        cpu_sustained_minutes: How long CPU must stay above the threshold to count.
        gpu_threshold: Mean accelerator-duty fraction (0-1) treated as GPU saturation.
        quota_usage_threshold: Fraction of a compute quota limit treated as capacity abuse.
        lookback_hours: Monitoring window queried for utilisation signals.
        max_instances: Cap on Compute Engine instances correlated per run.
        max_findings: Cap on SCC findings pulled per run.
    """

    model: str = field(
        default_factory=lambda: os.environ.get("CRYPTOJACK_GUARD_MODEL", DEFAULT_MODEL)
    )
    default_project_id: str = field(
        default_factory=lambda: (
            os.environ.get("CRYPTOJACK_GUARD_PROJECT_ID")
            or os.environ.get("IAM_GUARD_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        )
    )
    organization_id: str = field(
        default_factory=lambda: os.environ.get("CRYPTOJACK_GUARD_ORG_ID", "")
    )
    billing_account_id: str = field(
        default_factory=lambda: os.environ.get("CRYPTOJACK_GUARD_BILLING_ACCOUNT", "")
    )
    cpu_threshold: float = field(
        default_factory=lambda: _float_env("CRYPTOJACK_GUARD_CPU_THRESHOLD", 0.9)
    )
    cpu_sustained_minutes: int = field(
        default_factory=lambda: _int_env("CRYPTOJACK_GUARD_CPU_SUSTAINED_MINUTES", 120)
    )
    gpu_threshold: float = field(
        default_factory=lambda: _float_env("CRYPTOJACK_GUARD_GPU_THRESHOLD", 0.8)
    )
    quota_usage_threshold: float = field(
        default_factory=lambda: _float_env("CRYPTOJACK_GUARD_QUOTA_THRESHOLD", 0.8)
    )
    lookback_hours: int = field(
        default_factory=lambda: _int_env("CRYPTOJACK_GUARD_LOOKBACK_HOURS", 24)
    )
    max_instances: int = field(
        default_factory=lambda: _int_env("CRYPTOJACK_GUARD_MAX_INSTANCES", 500)
    )
    max_findings: int = field(
        default_factory=lambda: _int_env("CRYPTOJACK_GUARD_MAX_FINDINGS", 200)
    )


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def get_settings() -> Settings:
    """Reads settings from the environment on every call so redeploys pick up changes."""
    return Settings()
