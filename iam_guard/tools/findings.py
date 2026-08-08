"""Tools the reporting stage uses to pull rule-engine output out of session state."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext

from iam_guard.models import STATE_FINDINGS, Severity

_MAX_DETAIL_FINDINGS = 25


def list_findings(
    severity: str = "",
    category: str = "",
    service: str = "",
    limit: int = _MAX_DETAIL_FINDINGS,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Returns rule-engine findings, optionally filtered.

    Args:
        severity: Optional severity filter, one of CRITICAL, HIGH, MEDIUM, LOW.
        category: Optional threat category filter, e.g. ``cryptojacking``.
        service: Optional service filter, one of ``iam``, ``gce``, ``gcs``, ``bigquery``.
        limit: Maximum number of findings to return.

    Returns:
        The matching findings with full evidence and remediation commands.
    """
    if tool_context is None:
        return {"status": "error", "error": "Tool requires a session context."}

    findings: list[dict[str, Any]] = list(tool_context.state.get(STATE_FINDINGS) or [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.upper()]
    if category:
        findings = [f for f in findings if category.lower() in f.get("categories", [])]
    if service:
        findings = [f for f in findings if f.get("service") == service.lower()]

    limit = max(1, min(limit, _MAX_DETAIL_FINDINGS))
    return {
        "status": "ok",
        "match_count": len(findings),
        "returned": min(len(findings), limit),
        "findings": findings[:limit],
    }


def get_remediation_plan(tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Returns the ordered list of gcloud commands that close the detected findings.

    Returns:
        Remediation steps grouped by severity, highest severity first.
    """
    if tool_context is None:
        return {"status": "error", "error": "Tool requires a session context."}

    findings: list[dict[str, Any]] = list(tool_context.state.get(STATE_FINDINGS) or [])
    plan: list[dict[str, Any]] = []
    for severity in Severity:
        for finding in findings:
            if finding.get("severity") != severity.value or not finding.get("remediation_commands"):
                continue
            plan.append(
                {
                    "severity": severity.value,
                    "rule_id": finding.get("rule_id"),
                    "resource": finding.get("resource"),
                    "commands": finding.get("remediation_commands", []),
                }
            )
    return {"status": "ok", "step_count": len(plan), "steps": plan}
