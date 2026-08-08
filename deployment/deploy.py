#!/usr/bin/env python3
"""Deploys either agent to Agent Engine / Agent Runtime (Gemini Enterprise Agent Platform).

The deployed resource name (``projects/.../locations/.../reasoningEngines/...``) is
what you paste into Gemini Enterprise when registering a "Custom agent via Agent
Runtime", or what you pass to ``deployment/register_gemini_enterprise.py``.

Each agent deploys as its own reasoning engine, so they can be granted different
permissions and registered as separate Gemini Enterprise agents.

Examples:
    python deployment/deploy.py create \
        --project my-project --location us-central1 \
        --staging-bucket gs://my-project-agent-staging \
        --audit-project my-project

    python deployment/deploy.py create --agent cryptojack-guard \
        --project my-project --location us-central1 \
        --staging-bucket gs://my-project-agent-staging \
        --audit-project my-project --organization 123456789012 \
        --billing-account 0101AA-BBCCDD-223344

    python deployment/deploy.py list --project my-project --location us-central1
    python deployment/deploy.py delete --project my-project --location us-central1 \
        --resource-name projects/.../reasoningEngines/123
"""

from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import dataclass

import vertexai
from vertexai import agent_engines, types

IAM_GUARD = "iam-guard"
CRYPTOJACK_GUARD = "cryptojack-guard"

# Pinned so the runtime resolves the same dependency set that CI tests against.
_BASE_REQUIREMENTS = [
    "google-cloud-aiplatform[agent_engines,adk]>=1.112",
    "google-adk>=2.6,<3",
    "google-cloud-resource-manager>=1.14",
    "google-cloud-iam>=2.15",
    "google-cloud-compute>=1.19",
    # AdkApp is shipped to the runtime as a cloudpickle payload and the agent's
    # schemas are pydantic v2 models; neither is pulled in reliably as a transitive.
    "cloudpickle>=3.0",
    "pydantic>=2.0",
]

_IAM_GUARD_REQUIREMENTS = [
    *_BASE_REQUIREMENTS,
    "google-cloud-storage>=2.18",
    "google-cloud-bigquery>=3.25",
]

_CRYPTOJACK_REQUIREMENTS = [
    *_BASE_REQUIREMENTS,
    "google-cloud-monitoring>=2.21",
    "google-cloud-securitycenter>=1.31",
    "google-cloud-billing-budgets>=1.14",
    "google-cloud-org-policy>=1.10",
]


@dataclass(frozen=True)
class AgentSpec:
    """Everything that differs between the two deployments."""

    module: str
    display_name: str
    description: str
    requirements: list[str]
    extra_packages: list[str]
    roles: list[str]


AGENTS = {
    IAM_GUARD: AgentSpec(
        module="iam_guard.agent",
        display_name="IAM Guard - GCP IAM loophole auditor",
        description=(
            "Read-only Google Cloud IAM auditor. Reviews project IAM policies, service "
            "accounts and keys, Compute Engine, Cloud Storage and BigQuery, then reports "
            "privilege escalation, cryptojacking and phishing/account-takeover exposure "
            "with gcloud remediation commands. Ask it to 'audit IAM in project X'."
        ),
        requirements=_IAM_GUARD_REQUIREMENTS,
        extra_packages=["iam_guard"],
        # All read-only; the agent never mutates IAM.
        roles=[
            "roles/iam.securityReviewer",
            "roles/compute.viewer",
            "roles/storage.objectViewer",
            "roles/bigquery.metadataViewer",
        ],
    ),
    CRYPTOJACK_GUARD: AgentSpec(
        module="cryptojack_guard.agent",
        display_name="Cryptojack Guard - GCP cryptojacking detection",
        description=(
            "Advisory Google Cloud cryptojacking detector. Correlates Security Command "
            "Center threat findings, Cloud Monitoring utilisation, Compute quota usage, "
            "billing budgets, org policy guardrails and IAM preconditions, then explains "
            "what is mining and emits the containment and hardening commands for a human "
            "to apply. Read-only. Ask it to 'check project X for cryptojacking'."
        ),
        requirements=_CRYPTOJACK_REQUIREMENTS,
        # cryptojack_guard reuses iam_guard's collectors, models and rule engine.
        extra_packages=["cryptojack_guard", "iam_guard"],
        # All read-only. Budget and org policy roles are granted on the billing account
        # and the organisation respectively, not on the audited project.
        roles=[
            "roles/iam.securityReviewer",
            "roles/compute.viewer",
            "roles/monitoring.viewer",
            "roles/securitycenter.findingsViewer",
            "roles/orgpolicy.policyViewer",
            "roles/billing.viewer",
        ],
    ),
}


def _client(project: str, location: str) -> vertexai.Client:
    return vertexai.Client(project=project, location=location)


def _build_app(args: argparse.Namespace) -> tuple[agent_engines.AdkApp, dict[str, str]]:
    spec = AGENTS[args.agent]
    root_agent = importlib.import_module(spec.module).root_agent

    if args.agent == CRYPTOJACK_GUARD:
        env_vars = {"CRYPTOJACK_GUARD_MODEL": args.model}
        if args.audit_project:
            env_vars["CRYPTOJACK_GUARD_PROJECT_ID"] = args.audit_project
        if args.organization:
            env_vars["CRYPTOJACK_GUARD_ORG_ID"] = args.organization
        if args.billing_account:
            env_vars["CRYPTOJACK_GUARD_BILLING_ACCOUNT"] = args.billing_account
    else:
        env_vars = {"IAM_GUARD_MODEL": args.model}
        if args.audit_project:
            env_vars["IAM_GUARD_PROJECT_ID"] = args.audit_project
    if args.trusted_domains:
        env_vars["IAM_GUARD_TRUSTED_DOMAINS"] = args.trusted_domains
    return agent_engines.AdkApp(agent=root_agent, enable_tracing=True), env_vars


def create(args: argparse.Namespace) -> int:
    spec = AGENTS[args.agent]
    app, env_vars = _build_app(args)
    client = _client(args.project, args.location)

    remote_agent = client.agent_engines.create(
        agent=app,
        config={
            "display_name": spec.display_name,
            "description": spec.description,
            "requirements": spec.requirements,
            "extra_packages": spec.extra_packages,
            "staging_bucket": args.staging_bucket,
            "env_vars": env_vars,
            "identity_type": types.IdentityType.AGENT_IDENTITY,
        },
    )
    name = remote_agent.api_resource.name
    print(f"Deployed: {name}")
    print(
        "\nGrant the agent's service identity read-only access on each project you "
        "want it to inspect:\n"
        + "\n".join(
            f"  gcloud projects add-iam-policy-binding {args.audit_project or 'AUDITED_PROJECT'} "
            f'--member="serviceAccount:AGENT_SERVICE_IDENTITY" --role="{role}"'
            for role in spec.roles
        )
    )
    if args.agent == CRYPTOJACK_GUARD:
        print(
            "\nroles/billing.viewer must be granted on the billing account and "
            "roles/orgpolicy.policyViewer on the organisation, not on the project. "
            "Mining detections require Security Command Center; memory-based VM Threat "
            "Detection needs the Premium or Enterprise tier."
        )
    print(
        "\nRegister it with Gemini Enterprise:\n"
        f"  python deployment/register_gemini_enterprise.py --project {args.project} "
        f"--app-id YOUR_GEMINI_ENTERPRISE_APP_ID --reasoning-engine {name}"
    )
    return 0


def update(args: argparse.Namespace) -> int:
    spec = AGENTS[args.agent]
    app, env_vars = _build_app(args)
    client = _client(args.project, args.location)
    client.agent_engines.update(
        name=args.resource_name,
        agent=app,
        config={
            "display_name": spec.display_name,
            "description": spec.description,
            "requirements": spec.requirements,
            "extra_packages": spec.extra_packages,
            "staging_bucket": args.staging_bucket,
            "env_vars": env_vars,
        },
    )
    print(f"Updated: {args.resource_name}")
    return 0


def list_agents(args: argparse.Namespace) -> int:
    client = _client(args.project, args.location)
    for agent in client.agent_engines.list():
        print(f"{agent.api_resource.name}\t{agent.api_resource.display_name}")
    return 0


def delete(args: argparse.Namespace) -> int:
    client = _client(args.project, args.location)
    client.agent_engines.delete(name=args.resource_name, force=True)
    print(f"Deleted: {args.resource_name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["create", "update", "list", "delete"])
    parser.add_argument(
        "--agent",
        choices=sorted(AGENTS),
        default=IAM_GUARD,
        help="Which workflow agent to deploy. Defaults to iam-guard.",
    )
    parser.add_argument("--project", required=True, help="Project hosting Agent Runtime.")
    parser.add_argument("--location", default="us-central1")
    parser.add_argument(
        "--staging-bucket", help="gs:// bucket used to stage the deployment package."
    )
    parser.add_argument(
        "--audit-project",
        default="",
        help="Default project the deployed agent inspects.",
    )
    parser.add_argument(
        "--organization",
        default="",
        help="Numeric organisation id, for cryptojack-guard org policy reads.",
    )
    parser.add_argument(
        "--billing-account",
        default="",
        help="Billing account id, for cryptojack-guard budget reads.",
    )
    parser.add_argument("--model", default="gemini-3.6-flash")
    parser.add_argument(
        "--trusted-domains",
        default="",
        help="Comma separated internal domains, e.g. example.com,example.co.uk",
    )
    parser.add_argument("--resource-name", help="reasoningEngines resource, for update/delete.")
    args = parser.parse_args()

    if args.command in {"create", "update"} and not args.staging_bucket:
        parser.error("--staging-bucket is required for create and update")
    if args.command in {"update", "delete"} and not args.resource_name:
        parser.error("--resource-name is required for update and delete")

    return {
        "create": create,
        "update": update,
        "list": list_agents,
        "delete": delete,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
