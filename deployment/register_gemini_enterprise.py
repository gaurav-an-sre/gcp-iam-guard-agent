#!/usr/bin/env python3
"""Registers a deployed IAM Guard Agent Runtime endpoint with a Gemini Enterprise app.

Wraps the Discovery Engine ``.../assistants/default_assistant/agents`` API, so the
agent shows up in the Gemini Enterprise web app as a custom agent. Uses the
caller's gcloud credentials; requires the Gemini Enterprise Admin role and the
Discovery Engine API enabled.

Examples:
    python deployment/register_gemini_enterprise.py \
        --project my-project --app-id my-ge-app \
        --reasoning-engine projects/my-project/locations/us-central1/reasoningEngines/123

    python deployment/register_gemini_enterprise.py --project my-project \
        --app-id my-ge-app --list
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request

from deployment.deploy import DESCRIPTION, DISPLAY_NAME

API_VERSION = "v1alpha"


def _access_token() -> str:
    return subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _agents_url(args: argparse.Namespace) -> str:
    return (
        f"https://{args.endpoint_location}-discoveryengine.googleapis.com/{API_VERSION}"
        f"/projects/{args.project}/locations/{args.location}/collections/default_collection"
        f"/engines/{args.app_id}/assistants/default_assistant/agents"
    )


def _request(url: str, project: str, method: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {_access_token()}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": project,
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise SystemExit(f"{error.code} {error.reason} from {url}\n{detail}") from error


def register(args: argparse.Namespace) -> int:
    body: dict = {
        "displayName": args.display_name,
        "description": args.description,
        "adkAgentDefinition": {
            "provisionedReasoningEngine": {"reasoningEngine": args.reasoning_engine}
        },
    }
    if args.icon_uri:
        body["icon"] = {"uri": args.icon_uri}
    if args.authorization:
        body["authorizationConfig"] = {"toolAuthorizations": list(args.authorization)}

    agent = _request(_agents_url(args), args.project, "POST", body)
    print(json.dumps(agent, indent=2))
    print(
        "\nRegistered. Share it with users from the Gemini Enterprise console "
        "(Agents > the agent > Share), then ask it: "
        '"audit IAM in project PROJECT_ID".'
    )
    return 0


def list_agents(args: argparse.Namespace) -> int:
    print(json.dumps(_request(_agents_url(args), args.project, "GET"), indent=2))
    return 0


def unregister(args: argparse.Namespace) -> int:
    url = f"{_agents_url(args)}/{args.agent_id}"
    _request(url, args.project, "DELETE")
    print(f"Deleted agent {args.agent_id}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project", required=True, help="Project hosting the Gemini Enterprise app."
    )
    parser.add_argument("--app-id", required=True, help="Gemini Enterprise app (engine) id.")
    parser.add_argument(
        "--location", default="global", choices=["global", "us", "eu"], help="App multi-region."
    )
    parser.add_argument(
        "--endpoint-location",
        default="global",
        choices=["global", "us", "eu"],
        help="Discovery Engine endpoint multi-region.",
    )
    parser.add_argument("--reasoning-engine", help="projects/.../reasoningEngines/ID to register.")
    parser.add_argument("--display-name", default=DISPLAY_NAME)
    parser.add_argument("--description", default=DESCRIPTION)
    parser.add_argument("--icon-uri", default="")
    parser.add_argument(
        "--authorization",
        action="append",
        default=[],
        help="projects/NUMBER/locations/global/authorizations/AUTH_ID, repeatable.",
    )
    parser.add_argument("--list", action="store_true", help="List agents registered on the app.")
    parser.add_argument("--delete", dest="agent_id", help="Agent id to unregister.")
    args = parser.parse_args()

    if args.list:
        return list_agents(args)
    if args.agent_id:
        return unregister(args)
    if not args.reasoning_engine:
        parser.error("--reasoning-engine is required when registering")
    return register(args)


if __name__ == "__main__":
    sys.exit(main())
