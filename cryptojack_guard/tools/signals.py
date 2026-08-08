"""Tools the reporting stage uses to pull risk-engine output out of session state."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext

from cryptojack_guard.models import STATE_SIGNALS, Confidence, SignalKind

_MAX_DETAIL_SIGNALS = 25


def list_signals(
    confidence: str = "",
    kind: str = "",
    severity: str = "",
    source: str = "",
    limit: int = _MAX_DETAIL_SIGNALS,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Returns risk-engine signals, optionally filtered.

    Args:
        confidence: Optional filter, one of CONFIRMED, HIGH, MEDIUM, LOW.
        kind: Optional filter, ``detection`` or ``preventive``.
        severity: Optional filter, one of CRITICAL, HIGH, MEDIUM, LOW.
        source: Optional filter, e.g. ``scc``, ``monitoring``, ``compute``, ``billing``,
            ``org_policy``, ``iam``, ``correlation``.
        limit: Maximum number of signals to return.

    Returns:
        The matching signals with full evidence, investigation steps and advisory
        commands.
    """
    if tool_context is None:
        return {"status": "error", "error": "Tool requires a session context."}

    signals: list[dict[str, Any]] = list(tool_context.state.get(STATE_SIGNALS) or [])
    if confidence:
        signals = [s for s in signals if s.get("confidence") == confidence.upper()]
    if kind:
        signals = [s for s in signals if s.get("kind") == kind.lower()]
    if severity:
        signals = [s for s in signals if s.get("severity") == severity.upper()]
    if source:
        signals = [s for s in signals if s.get("source") == source.lower()]

    limit = max(1, min(limit, _MAX_DETAIL_SIGNALS))
    return {
        "status": "ok",
        "match_count": len(signals),
        "returned": min(len(signals), limit),
        "signals": signals[:limit],
    }


def get_response_plan(tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Returns the advisory response plan, ordered the way an incident should be worked.

    Containment of confirmed and likely mining comes first, then weaker detections that
    still need triage, then the preventive gaps that let it happen. Nothing here is
    executed: every command is for a human to review and run.

    Returns:
        Ordered steps, each naming the signal it comes from and why it is at that
        position in the plan.
    """
    if tool_context is None:
        return {"status": "error", "error": "Tool requires a session context."}

    signals: list[dict[str, Any]] = list(tool_context.state.get(STATE_SIGNALS) or [])
    phases = [
        (
            "contain",
            "Stop active abuse, preserving evidence first.",
            lambda s: (
                s.get("kind") == SignalKind.DETECTION.value
                and s.get("confidence") in {Confidence.CONFIRMED.value, Confidence.HIGH.value}
            ),
        ),
        (
            "triage",
            "Confirm or dismiss weaker detections before acting on them.",
            lambda s: (
                s.get("kind") == SignalKind.DETECTION.value
                and s.get("confidence") not in {Confidence.CONFIRMED.value, Confidence.HIGH.value}
            ),
        ),
        (
            "harden",
            "Close the gaps that make cryptojacking possible or invisible.",
            lambda s: s.get("kind") == SignalKind.PREVENTIVE.value,
        ),
    ]

    plan: list[dict[str, Any]] = []
    for phase, rationale, predicate in phases:
        for signal in signals:
            if not predicate(signal):
                continue
            plan.append(
                {
                    "phase": phase,
                    "phase_rationale": rationale,
                    "rule_id": signal.get("rule_id"),
                    "confidence": signal.get("confidence"),
                    "severity": signal.get("severity"),
                    "resource": signal.get("resource"),
                    "investigation": signal.get("investigation"),
                    "commands": signal.get("advisory_commands", []),
                }
            )
    return {
        "status": "ok",
        "step_count": len(plan),
        "applied_by": "human",
        "steps": plan,
    }
