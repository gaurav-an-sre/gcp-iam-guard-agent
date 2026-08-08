"""Custom ADK agent that runs the cryptojacking rule engine as a workflow step."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.genai import types

from cryptojack_guard.analysis import analyze
from cryptojack_guard.config import Settings, get_settings
from cryptojack_guard.models import (
    STATE_BUDGETS,
    STATE_MONITORING,
    STATE_ORG_POLICIES,
    STATE_QUOTAS,
    STATE_SCC_FINDINGS,
    STATE_SIGNALS,
    STATE_SUMMARY,
    summarize,
)
from iam_guard.models import (
    STATE_COLLECTION_ERRORS,
    STATE_GCE,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
)

_SIGNAL_KEYS = (
    STATE_SCC_FINDINGS,
    STATE_MONITORING,
    STATE_QUOTAS,
    STATE_BUDGETS,
    STATE_ORG_POLICIES,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
    STATE_GCE,
)


class RiskEngineAgent(BaseAgent):
    """Scores the collected signals with the deterministic cryptojacking rule set.

    Keeping this stage out of the LLM guarantees the same signals always produce the
    same verdict, and keeps raw telemetry out of the model context: only the aggregated
    summary reaches the reporting agent, which then pulls detail through tools.
    """

    settings: Settings = get_settings()

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        collected = {key: state.get(key) for key in _SIGNAL_KEYS}

        if not any(collected.values()):
            yield self._event(
                ctx,
                text=(
                    "No signals were collected, so no cryptojacking assessment is "
                    "possible. This is not a clean result: check the collection errors "
                    "and the agent's permissions before concluding anything."
                ),
                state_delta={STATE_SIGNALS: [], STATE_SUMMARY: summarize([])},
            )
            return

        signals = analyze(collected, self.settings)
        serialized = [signal.to_dict() for signal in signals]
        summary = summarize(signals)
        summary["collection_errors"] = state.get(STATE_COLLECTION_ERRORS) or {}
        summary["signals_collected"] = sorted(key for key, value in collected.items() if value)
        summary["top_signals"] = [
            {
                "rule_id": signal["rule_id"],
                "confidence": signal["confidence"],
                "severity": signal["severity"],
                "kind": signal["kind"],
                "title": signal["title"],
                "resource": signal["resource"],
            }
            for signal in serialized[:10]
        ]

        yield self._event(
            ctx,
            text=(
                "Risk engine complete. Verdict "
                f"{summary['verdict']}, {summary['total']} signal(s), cryptojacking risk "
                f"score {summary['cryptojacking_risk_score']}/100.\n"
                f"{json.dumps(summary, indent=2, default=str)}"
            ),
            state_delta={STATE_SIGNALS: serialized, STATE_SUMMARY: summary},
        )

    def _event(self, ctx: InvocationContext, text: str, state_delta: dict) -> Event:
        return Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            content=types.Content(role="model", parts=[types.Part(text=text)]),
            actions=EventActions(state_delta=state_delta),
        )
