"""Runtime configuration for the IAM Guard agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "gemini-3-flash-preview"

# Domains that are never expected to hold IAM bindings in a corporate project.
# Bindings for these are treated as a phishing / account-takeover foothold.
DEFAULT_UNTRUSTED_DOMAINS: tuple[str, ...] = (
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
)


def _split_env(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Settings resolved from the environment.

    Attributes:
        model: Gemini model used by every LlmAgent in the workflow.
        default_project_id: Project audited when the user does not name one.
        trusted_domains: Domains considered internal, e.g. ``example.com``.
        untrusted_domains: Consumer domains that should never hold bindings.
        max_buckets: Cap on Cloud Storage buckets inspected per run.
        max_datasets: Cap on BigQuery datasets inspected per run.
        max_instances: Cap on Compute Engine instances inspected per run.
    """

    model: str = field(default_factory=lambda: os.environ.get("IAM_GUARD_MODEL", DEFAULT_MODEL))
    default_project_id: str = field(
        default_factory=lambda: (
            os.environ.get("IAM_GUARD_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        )
    )
    trusted_domains: tuple[str, ...] = field(
        default_factory=lambda: _split_env("IAM_GUARD_TRUSTED_DOMAINS")
    )
    untrusted_domains: tuple[str, ...] = field(
        default_factory=lambda: (
            _split_env("IAM_GUARD_UNTRUSTED_DOMAINS") or DEFAULT_UNTRUSTED_DOMAINS
        )
    )
    max_buckets: int = field(
        default_factory=lambda: int(os.environ.get("IAM_GUARD_MAX_BUCKETS", "200"))
    )
    max_datasets: int = field(
        default_factory=lambda: int(os.environ.get("IAM_GUARD_MAX_DATASETS", "200"))
    )
    max_instances: int = field(
        default_factory=lambda: int(os.environ.get("IAM_GUARD_MAX_INSTANCES", "500"))
    )


def get_settings() -> Settings:
    """Reads settings from the environment on every call so redeploys pick up changes."""
    return Settings()
