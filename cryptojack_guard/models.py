"""Data model for cryptojacking signals.

Cryptojacking detection differs from IAM auditing in one important way: a
misconfiguration is either present or it is not, but "this project is mining" is a
judgement built from evidence of varying strength. A GPU VM, a pinned CPU or a
near-limit quota are all individually explainable by legitimate work. So every signal
carries an explicit :class:`Confidence` alongside its severity, and the report stage is
required to keep confirmed detections separate from suspicions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from iam_guard.models import Severity

# State keys written by the signal collectors and read by the rule engine.
STATE_SCC_FINDINGS = "scc_findings"
STATE_MONITORING = "monitoring_signals"
STATE_QUOTAS = "compute_quotas"
STATE_BUDGETS = "billing_budgets"
STATE_ORG_POLICIES = "org_policies"
STATE_SIGNALS = "cryptojack_signals"
STATE_SUMMARY = "cryptojack_summary"


class Confidence(str, Enum):
    """How strongly the evidence supports active cryptojacking.

    CONFIRMED is reserved for a threat detection product naming a mining workload;
    the rule engine never promotes correlated telemetry to CONFIRMED on its own.
    """

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        order = {
            Confidence.CONFIRMED: 0,
            Confidence.HIGH: 1,
            Confidence.MEDIUM: 2,
            Confidence.LOW: 3,
        }
        return order[self]


class SignalKind(str, Enum):
    """What the operator is expected to do with a signal.

    DETECTION means "investigate this workload now"; PREVENTIVE means "close this gap
    so the next attempt fails". Both are advisory: the agent never applies either.
    """

    DETECTION = "detection"
    PREVENTIVE = "preventive"


@dataclass
class Signal:
    """One cryptojacking detection or preventive gap.

    Attributes:
        rule_id: Stable identifier, e.g. ``CJ-SCC-MINING-FINDING``.
        title: One-line human readable summary.
        severity: Urgency, reusing IAM Guard's scale.
        confidence: Strength of the evidence for active mining.
        kind: Whether this is a detection or a preventive gap.
        source: Signal origin (``scc``, ``monitoring``, ``compute``, ``billing``,
            ``org_policy``, ``iam``, ``correlation``).
        resource: Resource the signal applies to.
        explanation: Why this evidence points at cryptojacking, and what would explain
            it innocently.
        investigation: Read-only checks a human runs to confirm or dismiss the signal.
        remediation: Human readable containment or hardening guidance.
        evidence: Structured facts supporting the signal.
        advisory_commands: Commands a human reviews and applies. Never run by the agent.
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    kind: SignalKind
    source: str
    resource: str
    explanation: str
    investigation: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    advisory_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["kind"] = self.kind.value
        return data


def sort_signals(signals: list[Signal]) -> list[Signal]:
    """Orders by confidence, then severity, then rule id and resource for stable output.

    Confidence leads because an operator responding to an incident must see confirmed
    detections before high-severity hardening advice.
    """
    return sorted(
        signals,
        key=lambda s: (s.confidence.rank, s.severity.rank, s.rule_id, s.resource),
    )


def dedupe_signals(signals: list[Signal]) -> list[Signal]:
    """Drops repeats of the same rule on the same resource, keeping the first."""
    seen: set[tuple[str, str]] = set()
    unique: list[Signal] = []
    for signal in signals:
        key = (signal.rule_id, signal.resource)
        if key in seen:
            continue
        seen.add(key)
        unique.append(signal)
    return unique


def summarize(signals: list[Signal]) -> dict[str, Any]:
    """Builds the counts and verdict the report stage opens with."""
    by_severity = {severity.value: 0 for severity in Severity}
    by_confidence = {confidence.value: 0 for confidence in Confidence}
    by_kind = {kind.value: 0 for kind in SignalKind}
    by_source: dict[str, int] = {}
    for signal in signals:
        by_severity[signal.severity.value] += 1
        by_confidence[signal.confidence.value] += 1
        by_kind[signal.kind.value] += 1
        by_source[signal.source] = by_source.get(signal.source, 0) + 1
    return {
        "total": len(signals),
        "verdict": verdict(signals),
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_kind": by_kind,
        "by_source": by_source,
        "cryptojacking_risk_score": risk_score(signals),
    }


def verdict(signals: list[Signal]) -> str:
    """Summarises the detection posture in one machine-checkable word.

    The report stage must not upgrade this: ``suspected`` never becomes ``confirmed``
    without a threat-detection product saying so.
    """
    detections = [s for s in signals if s.kind is SignalKind.DETECTION]
    if any(s.confidence is Confidence.CONFIRMED for s in detections):
        return "confirmed_mining"
    if any(s.confidence is Confidence.HIGH for s in detections):
        return "likely_mining"
    if detections:
        return "suspected_mining"
    if signals:
        return "no_detections_preventive_gaps"
    return "clean"


def risk_score(signals: list[Signal]) -> int:
    """Weighted 0-100 score combining evidence strength with urgency.

    Confidence multiplies severity so that a confirmed medium-severity detection
    outranks a pile of low-confidence hardening advice.
    """
    severity_weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 10,
        Severity.MEDIUM: 4,
        Severity.LOW: 1,
    }
    confidence_multipliers = {
        Confidence.CONFIRMED: 2.0,
        Confidence.HIGH: 1.5,
        Confidence.MEDIUM: 1.0,
        Confidence.LOW: 0.5,
    }
    total = sum(
        severity_weights[signal.severity] * confidence_multipliers[signal.confidence]
        for signal in signals
    )
    return min(int(total), 100)
