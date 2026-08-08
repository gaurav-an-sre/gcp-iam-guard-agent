"""Cryptojack Guard: an advisory ADK workflow agent that detects GCP cryptojacking.

Workflow shape::

    SequentialAgent "cryptojack_guard"
      1. LlmAgent      scope_agent            -> state["cryptojack_scope"]
      2. ParallelAgent signal_collectors
           - LlmAgent  scc_collector          -> state["scc_findings"]
           - LlmAgent  monitoring_collector   -> state["monitoring_signals"]
           - LlmAgent  capacity_collector     -> state["compute_quotas"], ["gce_inventory"]
           - LlmAgent  guardrail_collector    -> state["org_policies"], ["billing_budgets"],
                                                 ["project_iam"], ["service_accounts"]
      3. RiskEngineAgent risk_engine          -> state["cryptojack_signals"], ["cryptojack_summary"]
      4. LlmAgent      report_agent           -> state["cryptojack_report"]

Stage 2 runs four read-only collectors concurrently, stage 3 is deterministic Python
(no model call, and the only place a verdict is decided), and only stage 4 reasons over
the aggregated signals.

The agent is advisory: it detects, explains and emits the commands that would contain or
prevent cryptojacking, and a human applies them. No stage calls a mutating API.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent

from cryptojack_guard import prompts
from cryptojack_guard.config import get_settings
from cryptojack_guard.risk_engine_agent import RiskEngineAgent
from cryptojack_guard.tools.collectors import (
    collect_billing_budgets,
    collect_compute_quotas,
    collect_monitoring_signals,
    collect_org_policies,
    collect_scc_findings,
)
from cryptojack_guard.tools.signals import get_response_plan, list_signals
from iam_guard.tools.collectors import (
    collect_compute_inventory,
    collect_project_iam_policy,
    collect_service_accounts,
)

_settings = get_settings()

scope_agent = LlmAgent(
    name="scope_agent",
    model=_settings.model,
    description="Resolves the project to assess and whether this is an incident or a review.",
    instruction=prompts.SCOPE_INSTRUCTION.format(
        default_project_id=_settings.default_project_id or "(none configured)"
    ),
    output_key="cryptojack_scope",
)

scc_collector = LlmAgent(
    name="scc_collector",
    model=_settings.model,
    description="Collects active Security Command Center threat findings.",
    instruction=prompts.SCC_COLLECTOR_INSTRUCTION.format(cryptojack_scope="{cryptojack_scope}"),
    tools=[collect_scc_findings],
    output_key="scc_collection_report",
)

monitoring_collector = LlmAgent(
    name="monitoring_collector",
    model=_settings.model,
    description="Collects per-instance CPU and GPU utilisation from Cloud Monitoring.",
    instruction=prompts.MONITORING_COLLECTOR_INSTRUCTION.format(
        cryptojack_scope="{cryptojack_scope}"
    ),
    tools=[collect_monitoring_signals],
    output_key="monitoring_collection_report",
)

capacity_collector = LlmAgent(
    name="capacity_collector",
    model=_settings.model,
    description="Collects Compute Engine quota usage and the instance inventory.",
    instruction=prompts.CAPACITY_COLLECTOR_INSTRUCTION.format(
        cryptojack_scope="{cryptojack_scope}"
    ),
    tools=[collect_compute_quotas, collect_compute_inventory],
    output_key="capacity_collection_report",
)

guardrail_collector = LlmAgent(
    name="guardrail_collector",
    model=_settings.model,
    description="Collects org policy, billing budgets and the identity preconditions.",
    instruction=prompts.GUARDRAIL_COLLECTOR_INSTRUCTION.format(
        cryptojack_scope="{cryptojack_scope}"
    ),
    tools=[
        collect_org_policies,
        collect_billing_budgets,
        collect_project_iam_policy,
        collect_service_accounts,
    ],
    output_key="guardrail_collection_report",
)

signal_collectors = ParallelAgent(
    name="signal_collectors",
    description=(
        "Runs the read-only threat, utilisation, capacity and guardrail collectors concurrently."
    ),
    sub_agents=[scc_collector, monitoring_collector, capacity_collector, guardrail_collector],
)

risk_engine = RiskEngineAgent(
    name="risk_engine",
    description=(
        "Deterministically correlates the collected signals into cryptojacking "
        "detections and preventive gaps."
    ),
)

report_agent = LlmAgent(
    name="report_agent",
    model=_settings.model,
    description=(
        "Explains the signals, separates confirmed mining from suspicion, and emits the "
        "advisory response plan for a human to apply."
    ),
    instruction=prompts.REPORT_INSTRUCTION.format(cryptojack_summary="{cryptojack_summary}"),
    tools=[list_signals, get_response_plan],
    output_key="cryptojack_report",
)

root_agent = SequentialAgent(
    name="cryptojack_guard",
    description=(
        "Detects cryptojacking abuse of a Google Cloud project by correlating Security "
        "Command Center threat findings, Cloud Monitoring utilisation, Compute quota "
        "usage, billing budgets, org policy guardrails and IAM preconditions. Advisory "
        "and read-only: it emits containment and hardening commands for a human to "
        "apply. Ask it to 'check project X for cryptojacking'."
    ),
    sub_agents=[scope_agent, signal_collectors, risk_engine, report_agent],
)
