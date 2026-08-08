from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_inventory.json"


@pytest.fixture
def vulnerable_inventory() -> dict[str, Any]:
    with FIXTURE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def corporate_settings(monkeypatch: pytest.MonkeyPatch):
    from iam_guard.config import get_settings

    monkeypatch.setenv("IAM_GUARD_TRUSTED_DOMAINS", "example.com")
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "demo-prod-1234")
    return get_settings()


@pytest.fixture
def fixture_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_GUARD_FIXTURE", str(FIXTURE_PATH))
    monkeypatch.setenv("IAM_GUARD_PROJECT_ID", "demo-prod-1234")
    monkeypatch.setenv("IAM_GUARD_TRUSTED_DOMAINS", "example.com")


@pytest.fixture(autouse=True)
def _no_adc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards against tests accidentally reaching Google APIs."""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-only-not-used")
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    os.environ.pop("IAM_GUARD_UNTRUSTED_DOMAINS", None)
