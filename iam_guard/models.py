"""Data model shared by the collectors, the rule engine and the reporting agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

# State keys written by collector tools and read by the rule engine.
STATE_PROJECT_IAM = "project_iam"
STATE_SERVICE_ACCOUNTS = "service_accounts"
STATE_GCE = "gce_inventory"
STATE_GCS = "gcs_inventory"
STATE_BIGQUERY = "bigquery_inventory"
STATE_FINDINGS = "findings"
STATE_COLLECTION_ERRORS = "collection_errors"

PUBLIC_PRINCIPALS = frozenset({"allUsers", "allAuthenticatedUsers"})


class Severity(str, Enum):
    """Finding severity, ordered from most to least urgent."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        return order[self]


class ThreatCategory(str, Enum):
    """Attack outcome that a finding makes possible."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    CRYPTOJACKING = "cryptojacking"
    PHISHING_TAKEOVER = "phishing_takeover"
    DATA_EXFILTRATION = "data_exfiltration"
    PUBLIC_EXPOSURE = "public_exposure"
    WEAK_HYGIENE = "weak_hygiene"


@dataclass
class Finding:
    """A single IAM weakness detected on a resource.

    Attributes:
        rule_id: Stable identifier, e.g. ``IAM-GCS-PUBLIC-BUCKET``.
        title: One-line human readable summary.
        severity: Urgency of the finding.
        categories: Attack outcomes the weakness enables.
        service: GCP service the resource belongs to (``iam``, ``gce``, ``gcs``, ``bigquery``).
        resource: Fully qualified resource the finding applies to.
        principals: IAM principals implicated by the finding.
        roles: IAM roles implicated by the finding.
        evidence: Structured facts supporting the finding.
        explanation: Why an attacker cares about this weakness.
        remediation: Human readable remediation guidance.
        remediation_commands: ``gcloud`` commands that fix the finding.
    """

    rule_id: str
    title: str
    severity: Severity
    categories: list[ThreatCategory]
    service: str
    resource: str
    explanation: str
    remediation: str
    principals: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["categories"] = [category.value for category in self.categories]
        return data


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Orders findings by severity, then by rule id and resource for stable output."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource))


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Builds the counts the reporting agent uses to open its report."""
    by_severity = {severity.value: 0 for severity in Severity}
    by_category: dict[str, int] = {}
    by_service: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_service[finding.service] = by_service.get(finding.service, 0) + 1
        for category in finding.categories:
            by_category[category.value] = by_category.get(category.value, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_service": by_service,
        "risk_score": risk_score(findings),
    }


def risk_score(findings: list[Finding]) -> int:
    """Weighted 0-100 score; 0 means no findings, 100 means saturated with criticals."""
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 10,
        Severity.MEDIUM: 4,
        Severity.LOW: 1,
    }
    total = sum(weights[finding.severity] for finding in findings)
    return min(total, 100)
