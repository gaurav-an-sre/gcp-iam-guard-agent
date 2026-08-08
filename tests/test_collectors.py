from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from google.api_core import exceptions as gcp_exceptions
from google.auth import exceptions as auth_exceptions

from iam_guard.models import (
    STATE_BIGQUERY,
    STATE_COLLECTION_ERRORS,
    STATE_GCE,
    STATE_GCS,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
)
from iam_guard.tools import collectors


class FakeToolContext:
    """Minimal stand-in for ADK's ToolContext: only ``state`` is used by the tools."""

    def __init__(self) -> None:
        self.state: dict[str, Any] = {}


def test_project_iam_collector_records_state_from_fixture(fixture_env: None) -> None:
    context = FakeToolContext()
    summary = collectors.collect_project_iam_policy(tool_context=context)

    assert summary["status"] == "ok"
    assert summary["project_id"] == "demo-prod-1234"
    assert summary["public_members"] == ["allUsers"]
    assert summary["audit_configs_present"] is False
    assert context.state[STATE_PROJECT_IAM]["bindings"]


def test_storage_collector_reports_public_buckets(fixture_env: None) -> None:
    context = FakeToolContext()
    summary = collectors.collect_storage_inventory(tool_context=context)

    assert summary["public_buckets"] == ["demo-prod-public-assets"]
    assert len(context.state[STATE_GCS]["buckets"]) == 2


def test_compute_collector_reports_exposure(fixture_env: None) -> None:
    summary = collectors.collect_compute_inventory(tool_context=FakeToolContext())

    assert summary["instance_count"] == 2
    assert summary["internet_facing_instances"] == ["web-frontend-1"]
    assert summary["oslogin_enforced"] is False


def test_bigquery_collector_reports_broad_sharing(fixture_env: None) -> None:
    summary = collectors.collect_bigquery_inventory(tool_context=FakeToolContext())

    assert summary["dataset_count"] == 2
    assert summary["broadly_shared_datasets"] == ["customer_analytics"]


def test_missing_project_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_GUARD_FIXTURE", raising=False)
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "")

    assert collectors.collect_project_iam_policy()["status"] == "error"


def test_api_errors_are_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_GUARD_FIXTURE", raising=False)
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "demo-prod-1234")

    def boom(*_args: Any, **_kwargs: Any):
        raise gcp_exceptions.PermissionDenied("caller lacks resourcemanager.projects.getIamPolicy")

    monkeypatch.setattr(collectors.resourcemanager_v3, "ProjectsClient", boom)

    context = FakeToolContext()
    result = collectors.collect_project_iam_policy(tool_context=context)

    assert result["status"] == "error"
    assert "PermissionDenied" in result["error"]
    assert STATE_PROJECT_IAM in context.state[STATE_COLLECTION_ERRORS]


def test_missing_credentials_are_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_GUARD_FIXTURE", raising=False)
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "demo-prod-1234")

    def boom(*_args: Any, **_kwargs: Any):
        raise auth_exceptions.DefaultCredentialsError("could not automatically determine creds")

    monkeypatch.setattr(collectors.resourcemanager_v3, "ProjectsClient", boom)

    context = FakeToolContext()
    result = collectors.collect_project_iam_policy(tool_context=context)

    assert result["status"] == "error"
    assert "DefaultCredentialsError" in result["error"]
    assert STATE_PROJECT_IAM in context.state[STATE_COLLECTION_ERRORS]


@pytest.mark.parametrize("content", [None, "{not json"])
def test_unusable_fixture_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str | None
) -> None:
    path = tmp_path / "inventory.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("IAM_GUARD_FIXTURE", str(path))
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "demo-prod-1234")

    context = FakeToolContext()
    for tool in collectors.COLLECTOR_TOOLS:
        assert tool(tool_context=context)["status"] == "error"
    assert set(context.state[STATE_COLLECTION_ERRORS]) == {
        STATE_PROJECT_IAM,
        STATE_SERVICE_ACCOUNTS,
        STATE_GCE,
        STATE_GCS,
        STATE_BIGQUERY,
    }


def test_collectors_work_without_a_tool_context(fixture_env: None) -> None:
    for tool in collectors.COLLECTOR_TOOLS:
        assert tool()["status"] == "ok"
