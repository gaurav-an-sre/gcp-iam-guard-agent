"""IAM Guard: an ADK workflow agent that audits GCP IAM for abuse paths.

Workflow shape::

    SequentialAgent "iam_guard"
      1. LlmAgent      scope_agent            -> state["audit_scope"]
      2. ParallelAgent inventory_collectors
           - LlmAgent  iam_collector          -> state["project_iam"], ["service_accounts"]
           - LlmAgent  gce_collector          -> state["gce_inventory"]
           - LlmAgent  gcs_collector          -> state["gcs_inventory"]
           - LlmAgent  bigquery_collector     -> state["bigquery_inventory"]
      3. RuleEngineAgent rule_engine          -> state["findings"], ["findings_summary"]
      4. LlmAgent      report_agent           -> state["security_report"]

Stage 2 runs the four read-only collectors concurrently, stage 3 is deterministic
Python (no model call), and only stage 4 reasons over the aggregated findings.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent

from iam_guard import prompts
from iam_guard.config import get_settings
from iam_guard.rule_engine_agent import RuleEngineAgent
from iam_guard.tools.collectors import (
    collect_bigquery_inventory,
    collect_compute_inventory,
    collect_project_iam_policy,
    collect_service_accounts,
    collect_storage_inventory,
)
from iam_guard.tools.findings import get_remediation_plan, list_findings

_settings = get_settings()

scope_agent = LlmAgent(
    name="scope_agent",
    model=_settings.model,
    description="Resolves the project and services to audit.",
    instruction=prompts.SCOPE_INSTRUCTION.format(
        default_project_id=_settings.default_project_id or "(none configured)"
    ),
    output_key="audit_scope",
)

iam_collector = LlmAgent(
    name="iam_collector",
    model=_settings.model,
    description="Collects the project allow policy, audit configs and service accounts.",
    instruction=prompts.IAM_COLLECTOR_INSTRUCTION.format(audit_scope="{audit_scope}"),
    tools=[collect_project_iam_policy, collect_service_accounts],
    output_key="iam_collection_report",
)

gce_collector = LlmAgent(
    name="gce_collector",
    model=_settings.model,
    description="Collects Compute Engine instances, identities and exposure settings.",
    instruction=prompts.GCE_COLLECTOR_INSTRUCTION.format(audit_scope="{audit_scope}"),
    tools=[collect_compute_inventory],
    output_key="gce_collection_report",
)

gcs_collector = LlmAgent(
    name="gcs_collector",
    model=_settings.model,
    description="Collects Cloud Storage bucket policies and exposure controls.",
    instruction=prompts.GCS_COLLECTOR_INSTRUCTION.format(audit_scope="{audit_scope}"),
    tools=[collect_storage_inventory],
    output_key="gcs_collection_report",
)

bigquery_collector = LlmAgent(
    name="bigquery_collector",
    model=_settings.model,
    description="Collects BigQuery dataset access entries.",
    instruction=prompts.BIGQUERY_COLLECTOR_INSTRUCTION.format(audit_scope="{audit_scope}"),
    tools=[collect_bigquery_inventory],
    output_key="bigquery_collection_report",
)

inventory_collectors = ParallelAgent(
    name="inventory_collectors",
    description="Runs the read-only IAM, GCE, GCS and BigQuery collectors concurrently.",
    sub_agents=[iam_collector, gce_collector, gcs_collector, bigquery_collector],
)

rule_engine = RuleEngineAgent(
    name="rule_engine",
    description="Deterministically evaluates the collected inventory against the IAM rule set.",
)

report_agent = LlmAgent(
    name="report_agent",
    model=_settings.model,
    description="Explains the findings as attack paths and a prioritised remediation plan.",
    instruction=prompts.REPORT_INSTRUCTION.format(findings_summary="{findings_summary}"),
    tools=[list_findings, get_remediation_plan],
    output_key="security_report",
)

root_agent = SequentialAgent(
    name="iam_guard",
    description=(
        "Audits Google Cloud IAM on Compute Engine, Cloud Storage and BigQuery, and "
        "reports privilege escalation, cryptojacking and phishing exposure with "
        "remediation commands. Read-only."
    ),
    sub_agents=[scope_agent, inventory_collectors, rule_engine, report_agent],
)
