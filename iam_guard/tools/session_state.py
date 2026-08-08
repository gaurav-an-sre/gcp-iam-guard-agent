"""Shared session-state and fixture plumbing for the read-only collector tools.

Collectors in both workflows follow the same contract: write the full inventory to
session state under a well known key, return a small summary to the model, and turn
any credential, permission or fixture problem into a structured error that the
deterministic stage can report instead of an exception that aborts the run.
"""

from __future__ import annotations

import json
import os
from typing import Any

from google.adk.tools import ToolContext
from google.api_core import exceptions as gcp_exceptions
from google.auth import exceptions as auth_exceptions

from iam_guard.models import STATE_COLLECTION_ERRORS

#: Credential errors surface while building a client, API errors while calling it.
COLLECTION_ERRORS = (
    gcp_exceptions.GoogleAPIError,
    auth_exceptions.GoogleAuthError,
    OSError,
)


def record_inventory(tool_context: ToolContext | None, key: str, value: dict[str, Any]) -> None:
    """Stores a collected inventory in session state, if there is a session."""
    if tool_context is not None:
        tool_context.state[key] = value


def record_error(tool_context: ToolContext | None, key: str, message: str) -> None:
    """Adds ``message`` to the collection errors the report stage must disclose."""
    if tool_context is None:
        return
    errors = dict(tool_context.state.get(STATE_COLLECTION_ERRORS) or {})
    errors[key] = message
    tool_context.state[STATE_COLLECTION_ERRORS] = errors


def tool_failure(
    tool_context: ToolContext | None, key: str, error: Exception, hint: str
) -> dict[str, Any]:
    """Builds the tool response for a failed collection and records it in state."""
    message = f"{type(error).__name__}: {error}"
    record_error(tool_context, key, message)
    return {"status": "error", "error": message, "hint": hint}


def fixture_section(env_var: str, section: str) -> dict[str, Any] | None:
    """Reads one top-level section of the fixture named by ``env_var``."""
    path = os.environ.get(env_var)
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle).get(section)


def load_fixture(
    env_var: str, section: str, tool_context: ToolContext | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Returns ``(inventory, failure)``; both are None when running against live APIs."""
    try:
        return fixture_section(env_var, section), None
    except (OSError, ValueError) as error:
        return None, tool_failure(
            tool_context,
            section,
            error,
            f"Point {env_var} at a readable JSON inventory file, or unset it "
            "to collect from Google Cloud.",
        )


def missing_project() -> dict[str, Any]:
    """The response every collector returns when no project could be resolved."""
    return {"status": "error", "error": "No project_id supplied or configured."}
