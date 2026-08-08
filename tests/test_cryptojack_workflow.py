"""Tests for the Cryptojack Guard collectors, risk-engine stage and workflow shape.

The collectors are the only code that touches Google Cloud, so the tests that matter
most here are the negative ones: a missing tier, a missing role or a bad fixture must
become a disclosed collection error rather than an exception or a silent "clean".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent
from google.adk.runners import InMemoryRunner
from google.api_core import exceptions as gcp_exceptions
from google.auth import exceptions as auth_exceptions
from google.genai import types

from cryptojack_guard.agent import root_agent
from cryptojack_guard.models import (
    STATE_BUDGETS,
    STATE_MONITORING,
    STATE_ORG_POLICIES,
    STATE_QUOTAS,
    STATE_SCC_FINDINGS,
    STATE_SIGNALS,
    STATE_SUMMARY,
)
from cryptojack_guard.risk_engine_agent import RiskEngineAgent
from cryptojack_guard.tools import collectors
from cryptojack_guard.tools.signals import get_response_plan, list_signals
from iam_guard.models import STATE_COLLECTION_ERRORS, STATE_GCE
from tests.test_collectors import FakeToolContext

APP_NAME = "cryptojack-guard-test"

CRYPTOJACK_COLLECTORS = (
    (collectors.collect_scc_findings, STATE_SCC_FINDINGS),
    (collectors.collect_monitoring_signals, STATE_MONITORING),
    (collectors.collect_compute_quotas, STATE_QUOTAS),
    (collectors.collect_billing_budgets, STATE_BUDGETS),
    (collectors.collect_org_policies, STATE_ORG_POLICIES),
)


# --------------------------------------------------------------------------- #
# Collectors, fixture backed
# --------------------------------------------------------------------------- #


def test_scc_collector_summarises_categories(cryptojack_fixture_env: None) -> None:
    context = FakeToolContext()
    summary = collectors.collect_scc_findings(tool_context=context)

    assert summary["status"] == "ok"
    assert summary["finding_count"] == 4
    assert "Execution: Cryptocurrency Mining Hash Match" in summary["categories"]
    assert context.state[STATE_SCC_FINDINGS]["findings"]


def test_monitoring_collector_counts_pinned_instances(cryptojack_fixture_env: None) -> None:
    summary = collectors.collect_monitoring_signals(tool_context=FakeToolContext())

    assert summary["instances_measured"] == 4
    assert summary["instances_above_cpu_threshold"] == 2
    assert summary["gpu_metric_available"] is True


def test_quota_collector_reports_peak_utilisation(cryptojack_fixture_env: None) -> None:
    summary = collectors.collect_compute_quotas(tool_context=FakeToolContext())

    assert summary["regions_read"] == 3
    assert summary["max_quota_utilization"] == 0.95


def test_budget_collector_counts_budgets(cryptojack_fixture_env: None) -> None:
    summary = collectors.collect_billing_budgets(tool_context=FakeToolContext())

    assert summary["budget_count"] == 1
    assert summary["budgets_with_notifications"] == 1


def test_org_policy_collector_splits_enforced_from_gaps(cryptojack_fixture_env: None) -> None:
    summary = collectors.collect_org_policies(tool_context=FakeToolContext())

    assert summary["enforced"] == ["constraints/compute.disableNestedVirtualization"]
    assert "constraints/iam.disableServiceAccountKeyCreation" in summary["not_enforced"]


def test_collectors_work_without_a_tool_context(cryptojack_fixture_env: None) -> None:
    for collector, _ in CRYPTOJACK_COLLECTORS:
        assert collector()["status"] == "ok"


# --------------------------------------------------------------------------- #
# Collectors, failure paths
# --------------------------------------------------------------------------- #


def test_missing_project_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRYPTOJACK_GUARD_FIXTURE", raising=False)
    for name in (
        "CRYPTOJACK_GUARD_PROJECT_ID",
        "IAM_GUARD_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
    ):
        monkeypatch.setenv(name, "")

    for collector, _ in CRYPTOJACK_COLLECTORS:
        assert collector()["status"] == "error"


def test_missing_billing_account_is_reported_with_a_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Budgets live on the billing account, which the project id cannot imply."""
    monkeypatch.delenv("CRYPTOJACK_GUARD_FIXTURE", raising=False)
    monkeypatch.delenv("CRYPTOJACK_GUARD_BILLING_ACCOUNT", raising=False)
    monkeypatch.setenv("CRYPTOJACK_GUARD_PROJECT_ID", "demo-prod-1234")

    result = collectors.collect_billing_budgets(tool_context=FakeToolContext())

    assert result["status"] == "error"
    assert "CRYPTOJACK_GUARD_BILLING_ACCOUNT" in result["hint"]


@pytest.mark.parametrize(
    "error",
    [
        gcp_exceptions.PermissionDenied("caller lacks securitycenter.findings.list"),
        # What a Standard-tier project sees when it asks for threat findings.
        gcp_exceptions.FailedPrecondition("Security Command Center is not enabled"),
        auth_exceptions.DefaultCredentialsError("could not determine credentials"),
    ],
)
def test_scc_failures_are_disclosed_not_raised(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.delenv("CRYPTOJACK_GUARD_FIXTURE", raising=False)
    monkeypatch.setenv("CRYPTOJACK_GUARD_PROJECT_ID", "demo-prod-1234")

    def boom(*_args: Any, **_kwargs: Any):
        raise error

    monkeypatch.setattr(collectors.securitycenter_v1, "SecurityCenterClient", boom)

    context = FakeToolContext()
    result = collectors.collect_scc_findings(tool_context=context)

    assert result["status"] == "error"
    assert type(error).__name__ in result["error"]
    # The report must be able to say what could not be checked.
    assert STATE_SCC_FINDINGS in context.state[STATE_COLLECTION_ERRORS]
    assert "Premium or Enterprise" in result["hint"]


@pytest.mark.parametrize(
    ("client_module", "client_name", "collector", "key"),
    [
        (
            collectors.monitoring_v3,
            "MetricServiceClient",
            collectors.collect_monitoring_signals,
            STATE_MONITORING,
        ),
        (
            collectors.compute_v1,
            "RegionsClient",
            collectors.collect_compute_quotas,
            STATE_QUOTAS,
        ),
        (
            collectors.orgpolicy_v2,
            "OrgPolicyClient",
            collectors.collect_org_policies,
            STATE_ORG_POLICIES,
        ),
    ],
)
def test_api_failures_are_disclosed_not_raised(
    monkeypatch: pytest.MonkeyPatch,
    client_module: Any,
    client_name: str,
    collector: Any,
    key: str,
) -> None:
    monkeypatch.delenv("CRYPTOJACK_GUARD_FIXTURE", raising=False)
    monkeypatch.setenv("CRYPTOJACK_GUARD_PROJECT_ID", "demo-prod-1234")

    def boom(*_args: Any, **_kwargs: Any):
        raise gcp_exceptions.PermissionDenied("missing viewer role")

    monkeypatch.setattr(client_module, client_name, boom)

    context = FakeToolContext()
    result = collector(tool_context=context)

    assert result["status"] == "error"
    assert key in context.state[STATE_COLLECTION_ERRORS]


@pytest.mark.parametrize("content", [None, "{not json"])
def test_unusable_fixture_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str | None
) -> None:
    path = tmp_path / "signals.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("CRYPTOJACK_GUARD_FIXTURE", str(path))
    monkeypatch.setenv("CRYPTOJACK_GUARD_PROJECT_ID", "demo-prod-1234")

    context = FakeToolContext()
    for collector, _ in CRYPTOJACK_COLLECTORS:
        assert collector(tool_context=context)["status"] == "error"
    assert set(context.state[STATE_COLLECTION_ERRORS]) == {
        STATE_SCC_FINDINGS,
        STATE_MONITORING,
        STATE_QUOTAS,
        STATE_BUDGETS,
        STATE_ORG_POLICIES,
    }


def test_collectors_call_no_mutating_api() -> None:
    """A guard against a future edit reaching for a stop/patch/delete call."""
    source = Path(collectors.__file__).read_text(encoding="utf-8")
    forbidden = (
        ".stop(",
        ".delete(",
        ".insert(",
        ".patch(",
        ".update(",
        ".create(",
        ".set_iam_policy(",
        "SetIamPolicy",
        "disable_service_account",
    )

    assert [marker for marker in forbidden if marker in source] == []


# --------------------------------------------------------------------------- #
# Risk engine stage
# --------------------------------------------------------------------------- #


async def _run_risk_engine(state: dict[str, Any]) -> dict[str, Any]:
    engine = RiskEngineAgent(name="risk_engine", description="test")
    runner = InMemoryRunner(agent=engine, app_name=APP_NAME)
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id="tester", state=state
    )
    message = types.Content(role="user", parts=[types.Part(text="assess the signals")])
    async for _ in runner.run_async(user_id="tester", session_id=session.id, new_message=message):
        pass
    final = await runner.session_service.get_session(
        app_name=APP_NAME, user_id="tester", session_id=session.id
    )
    assert final is not None
    return final.state


async def test_risk_engine_writes_signals_and_summary(
    cryptojacked_signals: dict[str, Any], cryptojack_settings: Any, corporate_settings: Any
) -> None:
    state = await _run_risk_engine(dict(cryptojacked_signals))

    summary = state[STATE_SUMMARY]
    assert summary["verdict"] == "confirmed_mining"
    assert summary["total"] == len(state[STATE_SIGNALS]) > 0
    assert STATE_SCC_FINDINGS in summary["signals_collected"]
    assert summary["top_signals"][0]["confidence"] == "CONFIRMED"
    # Agent Engine persists session state remotely, so it must stay serialisable.
    json.dumps(state)


async def test_risk_engine_refuses_to_call_no_signals_clean() -> None:
    state = await _run_risk_engine({})

    assert state[STATE_SIGNALS] == []
    assert state[STATE_SUMMARY]["verdict"] == "clean"


async def test_risk_engine_discloses_collection_errors(
    cryptojack_settings: Any, corporate_settings: Any
) -> None:
    state = await _run_risk_engine(
        {
            STATE_GCE: {"project_id": "demo", "instances": []},
            STATE_COLLECTION_ERRORS: {STATE_SCC_FINDINGS: "PermissionDenied: no findings access"},
        }
    )

    assert state[STATE_SUMMARY]["collection_errors"][STATE_SCC_FINDINGS]


# --------------------------------------------------------------------------- #
# Reporting tools
# --------------------------------------------------------------------------- #


def test_signal_tools_filter_and_order_the_response_plan(
    cryptojacked_signals: dict[str, Any], cryptojack_settings: Any, corporate_settings: Any
) -> None:
    from cryptojack_guard.analysis import analyze

    context = FakeToolContext()
    context.state[STATE_SIGNALS] = [
        signal.to_dict() for signal in analyze(cryptojacked_signals, cryptojack_settings)
    ]

    confirmed = list_signals(confidence="confirmed", tool_context=context)
    assert confirmed["match_count"] > 0
    assert {s["confidence"] for s in confirmed["signals"]} == {"CONFIRMED"}

    preventive = list_signals(kind="preventive", tool_context=context)
    assert {s["kind"] for s in preventive["signals"]} == {"preventive"}

    scc_only = list_signals(source="scc", tool_context=context)
    assert {s["source"] for s in scc_only["signals"]} == {"scc"}

    plan = get_response_plan(tool_context=context)
    assert plan["applied_by"] == "human"
    phases = [step["phase"] for step in plan["steps"]]
    # Containment first, hardening last: an operator works the plan top down.
    assert phases == sorted(phases, key=["contain", "triage", "harden"].index)
    assert phases[0] == "contain"


def test_signal_tools_require_a_session() -> None:
    assert list_signals()["status"] == "error"
    assert get_response_plan()["status"] == "error"


# --------------------------------------------------------------------------- #
# Workflow shape
# --------------------------------------------------------------------------- #


def test_workflow_shape() -> None:
    assert isinstance(root_agent, SequentialAgent)
    assert [agent.name for agent in root_agent.sub_agents] == [
        "scope_agent",
        "signal_collectors",
        "risk_engine",
        "report_agent",
    ]

    signal_collectors = root_agent.sub_agents[1]
    assert isinstance(signal_collectors, ParallelAgent)
    assert [agent.name for agent in signal_collectors.sub_agents] == [
        "scc_collector",
        "monitoring_collector",
        "capacity_collector",
        "guardrail_collector",
    ]
    # The verdict is decided in Python, never by a model.
    assert isinstance(root_agent.sub_agents[2], RiskEngineAgent)
    assert isinstance(root_agent.sub_agents[3], LlmAgent)


def _walk(agent):
    yield agent
    for child in agent.sub_agents or []:
        yield from _walk(child)


def test_every_stage_has_a_description_and_the_expected_tools() -> None:
    for agent in _walk(root_agent):
        assert agent.description, f"{agent.name} has no description"

    tool_names = {
        tool.__name__
        for agent in _walk(root_agent)
        if isinstance(agent, LlmAgent)
        for tool in agent.tools
    }
    assert {
        "collect_scc_findings",
        "collect_monitoring_signals",
        "collect_compute_quotas",
        "collect_org_policies",
        "collect_billing_budgets",
        "list_signals",
        "get_response_plan",
    } <= tool_names


def test_report_prompt_forbids_acting_and_forbids_upgrading_confidence() -> None:
    from cryptojack_guard import prompts

    instruction = prompts.REPORT_INSTRUCTION.lower()
    for phrase in ("never", "human", "advisory"):
        assert phrase in instruction
