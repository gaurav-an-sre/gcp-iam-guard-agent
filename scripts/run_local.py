#!/usr/bin/env python3
"""Runs the IAM Guard workflow locally, end to end.

Examples:
    # Live audit of a real project (requires `gcloud auth application-default login`)
    python scripts/run_local.py --project my-project

    # Offline run against the recorded inventory, no GCP access needed
    IAM_GUARD_FIXTURE=examples/vulnerable_inventory.json \
        python scripts/run_local.py --project demo-prod-1234

    # Rule engine only, no model calls and no credentials at all
    python scripts/run_local.py --rules-only examples/vulnerable_inventory.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from google.genai import types

APP_NAME = "iam-guard"


def _run_rules_only(path: str) -> int:
    from iam_guard.analysis import analyze
    from iam_guard.models import summarize

    with open(path, encoding="utf-8") as handle:
        inventory = json.load(handle)

    findings = analyze(inventory)
    print(json.dumps(summarize(findings), indent=2))
    for finding in findings:
        print(f"{finding.severity.value:<8} {finding.rule_id:<34} {finding.title}")
    return 0


async def _run_agent(project_id: str, prompt: str) -> int:
    from google.adk.runners import InMemoryRunner

    from iam_guard.agent import root_agent
    from iam_guard.models import STATE_FINDINGS

    runner = InMemoryRunner(agent=root_agent, app_name=APP_NAME)
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id="local-user")

    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    async for event in runner.run_async(
        user_id="local-user", session_id=session.id, new_message=message
    ):
        for part in (event.content.parts if event.content else []) or []:
            if part.text:
                print(f"\n--- {event.author} ---\n{part.text}")

    final = await runner.session_service.get_session(
        app_name=APP_NAME, user_id="local-user", session_id=session.id
    )
    findings = (final.state if final else {}).get(STATE_FINDINGS) or []
    print(f"\n=== {len(findings)} finding(s) recorded in session state ===")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", help="GCP project id to audit.")
    parser.add_argument(
        "--rules-only",
        metavar="INVENTORY_JSON",
        help="Skip the agents and run the rule engine over a recorded inventory.",
    )
    parser.add_argument(
        "--prompt",
        default=(
            "Audit IAM on IAM, Compute Engine, Cloud Storage and BigQuery in project {project}."
        ),
        help="Prompt sent to the workflow. '{project}' is substituted.",
    )
    args = parser.parse_args()

    if args.rules_only:
        return _run_rules_only(args.rules_only)

    if not args.project:
        parser.error("--project is required unless --rules-only is used")
    os.environ.setdefault("IAM_GUARD_PROJECT_ID", args.project)
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "1")
    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", args.project)

    return asyncio.run(_run_agent(args.project, args.prompt.format(project=args.project)))


if __name__ == "__main__":
    sys.exit(main())
