"""Custom ADK agent that runs the IAM rule engine as a deterministic workflow step."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.genai import types

from iam_guard.analysis import analyze
from iam_guard.config import Settings, get_settings
from iam_guard.models import (
    STATE_BIGQUERY,
    STATE_COLLECTION_ERRORS,
    STATE_FINDINGS,
    STATE_GCE,
    STATE_GCS,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
    summarize,
)

STATE_SUMMARY = "findings_summary"

_INVENTORY_KEYS = (
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
    STATE_GCE,
    STATE_GCS,
    STATE_BIGQUERY,
)


class RuleEngineAgent(BaseAgent):
    """Analyses the collected inventory with the deterministic rule set.

    Keeping this stage out of the LLM guarantees the same inventory always
    produces the same findings, and keeps large IAM policies out of the model
    context: only the aggregated summary is surfaced to the reporting agent.
    """

    settings: Settings = get_settings()

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        inventory = {key: state.get(key) for key in _INVENTORY_KEYS}

        if not any(inventory.values()):
            yield self._event(
                ctx,
                text=(
                    "No inventory was collected, so there is nothing to analyse. "
                    "Check the collection errors and the agent's IAM permissions."
                ),
                state_delta={STATE_FINDINGS: [], STATE_SUMMARY: summarize([])},
            )
            return

        findings = analyze(inventory, self.settings)
        serialized = [finding.to_dict() for finding in findings]
        summary = summarize(findings)
        summary["collection_errors"] = state.get(STATE_COLLECTION_ERRORS) or {}
        summary["top_findings"] = [
            {
                "rule_id": finding["rule_id"],
                "severity": finding["severity"],
                "title": finding["title"],
                "resource": finding["resource"],
                "categories": finding["categories"],
            }
            for finding in serialized[:10]
        ]

        yield self._event(
            ctx,
            text=(
                "Rule engine complete. "
                f"{summary['total']} finding(s), risk score {summary['risk_score']}/100.\n"
                f"{json.dumps(summary, indent=2, default=str)}"
            ),
            state_delta={STATE_FINDINGS: serialized, STATE_SUMMARY: summary},
        )

    def _event(self, ctx: InvocationContext, text: str, state_delta: dict) -> Event:
        return Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            content=types.Content(role="model", parts=[types.Part(text=text)]),
            actions=EventActions(state_delta=state_delta),
        )
