from __future__ import annotations

import json
from typing import Any

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from iam_guard.agent import root_agent
from iam_guard.models import STATE_FINDINGS
from iam_guard.rule_engine_agent import STATE_SUMMARY, RuleEngineAgent
from iam_guard.tools.findings import get_remediation_plan, list_findings
from tests.test_collectors import FakeToolContext

APP_NAME = "iam-guard-test"


def test_workflow_shape() -> None:
    assert isinstance(root_agent, SequentialAgent)
    stages = [agent.name for agent in root_agent.sub_agents]
    assert stages == ["scope_agent", "inventory_collectors", "rule_engine", "report_agent"]

    collectors = root_agent.sub_agents[1]
    assert isinstance(collectors, ParallelAgent)
    assert [agent.name for agent in collectors.sub_agents] == [
        "iam_collector",
        "gce_collector",
        "gcs_collector",
        "bigquery_collector",
    ]
    assert isinstance(root_agent.sub_agents[2], RuleEngineAgent)
    assert isinstance(root_agent.sub_agents[3], LlmAgent)


def test_every_llm_stage_declares_tools_and_description() -> None:
    def walk(agent):
        yield agent
        for child in agent.sub_agents or []:
            yield from walk(child)

    for agent in walk(root_agent):
        assert agent.description, f"{agent.name} has no description"

    tool_names = {
        tool.__name__
        for agent in walk(root_agent)
        if isinstance(agent, LlmAgent)
        for tool in agent.tools
    }
    assert "collect_project_iam_policy" in tool_names
    assert "list_findings" in tool_names


async def _run_rule_engine(state: dict[str, Any]) -> dict[str, Any]:
    engine = RuleEngineAgent(name="rule_engine", description="test")
    runner = InMemoryRunner(agent=engine, app_name=APP_NAME)
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id="tester", state=state
    )
    message = types.Content(role="user", parts=[types.Part(text="analyse the inventory")])
    async for _ in runner.run_async(user_id="tester", session_id=session.id, new_message=message):
        pass
    final = await runner.session_service.get_session(
        app_name=APP_NAME, user_id="tester", session_id=session.id
    )
    assert final is not None
    return final.state


async def test_rule_engine_agent_writes_findings_to_state(
    vulnerable_inventory: dict[str, Any], corporate_settings: Any
) -> None:
    state = await _run_rule_engine(dict(vulnerable_inventory))

    findings = state[STATE_FINDINGS]
    summary = state[STATE_SUMMARY]
    assert summary["total"] == len(findings) > 0
    assert summary["by_severity"]["CRITICAL"] > 0
    assert summary["risk_score"] > 0
    assert len(summary["top_findings"]) == 10
    # State must stay JSON-serialisable: Agent Engine persists it remotely.
    json.dumps(state)


async def test_rule_engine_agent_handles_empty_inventory() -> None:
    state = await _run_rule_engine({})

    assert state[STATE_FINDINGS] == []
    assert state[STATE_SUMMARY]["total"] == 0


def test_finding_tools_filter_and_build_a_plan(
    vulnerable_inventory: dict[str, Any], corporate_settings: Any
) -> None:
    from iam_guard.analysis import analyze

    context = FakeToolContext()
    context.state[STATE_FINDINGS] = [
        f.to_dict() for f in analyze(vulnerable_inventory, corporate_settings)
    ]

    criticals = list_findings(severity="critical", tool_context=context)
    assert criticals["match_count"] > 0
    assert {f["severity"] for f in criticals["findings"]} == {"CRITICAL"}

    cryptojacking = list_findings(category="cryptojacking", tool_context=context)
    assert cryptojacking["match_count"] > 0

    gcs_only = list_findings(service="gcs", tool_context=context)
    assert {f["service"] for f in gcs_only["findings"]} == {"gcs"}

    plan = get_remediation_plan(tool_context=context)
    assert plan["step_count"] > 0
    assert plan["steps"][0]["severity"] == "CRITICAL"
    assert all(step["commands"] for step in plan["steps"])


def test_finding_tools_require_a_session() -> None:
    assert list_findings()["status"] == "error"
    assert get_remediation_plan()["status"] == "error"
