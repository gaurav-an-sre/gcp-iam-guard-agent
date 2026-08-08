#!/usr/bin/env python3
"""Runs either workflow agent locally, end to end.

Examples:
    # Live IAM audit of a real project (requires `gcloud auth application-default login`)
    python scripts/run_local.py --project my-project

    # Offline run against the recorded inventory, no GCP access needed
    IAM_GUARD_FIXTURE=examples/vulnerable_inventory.json \
        python scripts/run_local.py --project demo-prod-1234

    # Rule engine only, no model calls and no credentials at all
    python scripts/run_local.py --rules-only examples/vulnerable_inventory.json

    # Cryptojacking assessment, rules only
    python scripts/run_local.py --agent cryptojack-guard \
        --rules-only examples/cryptojacked_project.json

    # Cryptojacking assessment through the full workflow, offline
    CRYPTOJACK_GUARD_FIXTURE=examples/cryptojacked_project.json \
        IAM_GUARD_FIXTURE=examples/cryptojacked_project.json \
        python scripts/run_local.py --agent cryptojack-guard --project demo-prod-1234
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from google.auth import exceptions as auth_exceptions
from google.genai import types

IAM_GUARD = "iam-guard"
CRYPTOJACK_GUARD = "cryptojack-guard"

_PROMPTS = {
    IAM_GUARD: "Audit IAM on IAM, Compute Engine, Cloud Storage and BigQuery in project {project}.",
    CRYPTOJACK_GUARD: "Check project {project} for cryptojacking abuse.",
}

_PROJECT_ENV_VARS = {
    IAM_GUARD: "IAM_GUARD_PROJECT_ID",
    CRYPTOJACK_GUARD: "CRYPTOJACK_GUARD_PROJECT_ID",
}


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def _load_json(path: str) -> dict | int:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as error:
        return _fail(f"cannot read inventory {path}: {error.strerror or error}")
    except json.JSONDecodeError as error:
        return _fail(f"{path} is not valid JSON: {error}")


def _run_rules_only(agent: str, path: str) -> int:
    collected = _load_json(path)
    if isinstance(collected, int):
        return collected

    if agent == CRYPTOJACK_GUARD:
        from cryptojack_guard.analysis import analyze
        from cryptojack_guard.models import summarize

        signals = analyze(collected)
        print(json.dumps(summarize(signals), indent=2))
        for signal in signals:
            print(
                f"{signal.confidence.value:<10} {signal.severity.value:<8} "
                f"{signal.rule_id:<44} {signal.title}"
            )
        return 0

    from iam_guard.analysis import analyze
    from iam_guard.models import summarize

    findings = analyze(collected)
    print(json.dumps(summarize(findings), indent=2))
    for finding in findings:
        print(f"{finding.severity.value:<8} {finding.rule_id:<34} {finding.title}")
    return 0


async def _run_agent(agent: str, prompt: str) -> int:
    from google.adk.runners import InMemoryRunner

    if agent == CRYPTOJACK_GUARD:
        from cryptojack_guard.agent import root_agent
        from cryptojack_guard.models import STATE_SIGNALS as result_key

        label = "signal"
    else:
        from iam_guard.agent import root_agent
        from iam_guard.models import STATE_FINDINGS as result_key

        label = "finding"

    runner = InMemoryRunner(agent=root_agent, app_name=agent)
    session = await runner.session_service.create_session(app_name=agent, user_id="local-user")

    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    async for event in runner.run_async(
        user_id="local-user", session_id=session.id, new_message=message
    ):
        for part in (event.content.parts if event.content else []) or []:
            if part.text:
                print(f"\n--- {event.author} ---\n{part.text}")

    final = await runner.session_service.get_session(
        app_name=agent, user_id="local-user", session_id=session.id
    )
    results = (final.state if final else {}).get(result_key) or []
    print(f"\n=== {len(results)} {label}(s) recorded in session state ===")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agent",
        choices=[IAM_GUARD, CRYPTOJACK_GUARD],
        default=IAM_GUARD,
        help="Which workflow agent to run. Defaults to iam-guard.",
    )
    parser.add_argument("--project", help="GCP project id to inspect.")
    parser.add_argument(
        "--rules-only",
        metavar="INVENTORY_JSON",
        help="Skip the agents and run the rule engine over a recorded inventory.",
    )
    parser.add_argument(
        "--prompt",
        help="Prompt sent to the workflow. '{project}' is substituted.",
    )
    args = parser.parse_args()

    if args.rules_only:
        return _run_rules_only(args.agent, args.rules_only)

    if not args.project:
        parser.error("--project is required unless --rules-only is used")
    os.environ.setdefault(_PROJECT_ENV_VARS[args.agent], args.project)
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "1")
    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", args.project)

    prompt = (args.prompt or _PROMPTS[args.agent]).format(project=args.project)
    try:
        return asyncio.run(_run_agent(args.agent, prompt))
    except auth_exceptions.GoogleAuthError as error:
        fixture_var = (
            "CRYPTOJACK_GUARD_FIXTURE" if args.agent == CRYPTOJACK_GUARD else "IAM_GUARD_FIXTURE"
        )
        return _fail(
            f"Google Cloud credentials are missing or invalid ({type(error).__name__}). "
            "Run 'gcloud auth application-default login' and make sure the Vertex AI API "
            f"is enabled on project {args.project}. To try the agent without any GCP "
            f"access, set {fixture_var} to a recorded inventory, or use --rules-only."
        )


if __name__ == "__main__":
    sys.exit(main())
