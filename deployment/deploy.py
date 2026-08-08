#!/usr/bin/env python3
"""Deploys IAM Guard to Agent Engine / Agent Runtime (Gemini Enterprise Agent Platform).

The deployed resource name (``projects/.../locations/.../reasoningEngines/...``) is
what you paste into Gemini Enterprise when registering a "Custom agent via Agent
Runtime", or what you pass to ``deployment/register_gemini_enterprise.py``.

Examples:
    python deployment/deploy.py create \
        --project my-project --location us-central1 \
        --staging-bucket gs://my-project-agent-staging \
        --audit-project my-project

    python deployment/deploy.py list --project my-project --location us-central1
    python deployment/deploy.py delete --project my-project --location us-central1 \
        --resource-name projects/.../reasoningEngines/123
"""

from __future__ import annotations

import argparse
import sys

import vertexai
from vertexai import agent_engines, types

DISPLAY_NAME = "IAM Guard - GCP IAM loophole auditor"
DESCRIPTION = (
    "Read-only Google Cloud IAM auditor. Reviews project IAM policies, service "
    "accounts and keys, Compute Engine, Cloud Storage and BigQuery, then reports "
    "privilege escalation, cryptojacking and phishing/account-takeover exposure "
    "with gcloud remediation commands. Ask it to 'audit IAM in project X'."
)

# Pinned so the runtime resolves the same dependency set that CI tests against.
REQUIREMENTS = [
    "google-cloud-aiplatform[agent_engines,adk]>=1.112",
    "google-adk>=2.6,<3",
    "google-cloud-resource-manager>=1.14",
    "google-cloud-iam>=2.15",
    "google-cloud-compute>=1.19",
    "google-cloud-storage>=2.18",
    "google-cloud-bigquery>=3.25",
]

# Roles the agent's service identity needs on every audited project. All are
# read-only; the agent never mutates IAM.
REQUIRED_AUDIT_ROLES = [
    "roles/iam.securityReviewer",
    "roles/compute.viewer",
    "roles/storage.objectViewer",
    "roles/bigquery.metadataViewer",
]


def _client(project: str, location: str) -> vertexai.Client:
    return vertexai.Client(project=project, location=location)


def _build_app(audit_project: str, model: str, trusted_domains: str):
    from iam_guard.agent import root_agent

    env_vars = {"IAM_GUARD_MODEL": model}
    if audit_project:
        env_vars["IAM_GUARD_PROJECT_ID"] = audit_project
    if trusted_domains:
        env_vars["IAM_GUARD_TRUSTED_DOMAINS"] = trusted_domains
    return agent_engines.AdkApp(agent=root_agent, enable_tracing=True), env_vars


def create(args: argparse.Namespace) -> int:
    app, env_vars = _build_app(args.audit_project, args.model, args.trusted_domains)
    client = _client(args.project, args.location)

    remote_agent = client.agent_engines.create(
        agent=app,
        config={
            "display_name": DISPLAY_NAME,
            "description": DESCRIPTION,
            "requirements": REQUIREMENTS,
            "extra_packages": ["iam_guard"],
            "staging_bucket": args.staging_bucket,
            "env_vars": env_vars,
            "identity_type": types.IdentityType.AGENT_IDENTITY,
        },
    )
    name = remote_agent.api_resource.name
    print(f"Deployed: {name}")
    print(
        "\nGrant the agent's service identity read-only access on each project you "
        "want it to audit:\n"
        + "\n".join(
            f"  gcloud projects add-iam-policy-binding {args.audit_project or 'AUDITED_PROJECT'} "
            f'--member="serviceAccount:AGENT_SERVICE_IDENTITY" --role="{role}"'
            for role in REQUIRED_AUDIT_ROLES
        )
    )
    print(
        "\nRegister it with Gemini Enterprise:\n"
        f"  python deployment/register_gemini_enterprise.py --project {args.project} "
        f"--app-id YOUR_GEMINI_ENTERPRISE_APP_ID --reasoning-engine {name}"
    )
    return 0


def update(args: argparse.Namespace) -> int:
    app, env_vars = _build_app(args.audit_project, args.model, args.trusted_domains)
    client = _client(args.project, args.location)
    client.agent_engines.update(
        name=args.resource_name,
        agent=app,
        config={
            "display_name": DISPLAY_NAME,
            "description": DESCRIPTION,
            "requirements": REQUIREMENTS,
            "extra_packages": ["iam_guard"],
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
    parser.add_argument("--project", required=True, help="Project hosting Agent Runtime.")
    parser.add_argument("--location", default="us-central1")
    parser.add_argument(
        "--staging-bucket", help="gs:// bucket used to stage the deployment package."
    )
    parser.add_argument(
        "--audit-project",
        default="",
        help="Default project the deployed agent audits (IAM_GUARD_PROJECT_ID).",
    )
    parser.add_argument("--model", default="gemini-2.5-flash")
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
