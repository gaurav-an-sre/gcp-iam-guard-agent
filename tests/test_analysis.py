from __future__ import annotations

from typing import Any

import pytest

from iam_guard.analysis import analyze, check_attack_paths, check_gcs, check_project_iam
from iam_guard.config import Settings
from iam_guard.models import Severity, ThreatCategory


def rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def by_rule(findings, rule_id: str) -> list:
    return [finding for finding in findings if finding.rule_id == rule_id]


@pytest.fixture
def settings() -> Settings:
    return Settings(
        trusted_domains=("example.com",), untrusted_domains=("gmail.com", "outlook.com")
    )


def test_clean_project_produces_no_high_findings(settings: Settings) -> None:
    inventory: dict[str, Any] = {
        "project_iam": {
            "project_id": "clean",
            "bindings": [
                {
                    "role": "roles/bigquery.metadataViewer",
                    "members": ["group:reviewers@example.com"],
                    "condition": None,
                }
            ],
            "audit_configs": [{"service": "storage.googleapis.com", "log_types": ["DATA_READ"]}],
        }
    }
    findings = analyze(inventory, settings)
    assert [f for f in findings if f.severity in {Severity.CRITICAL, Severity.HIGH}] == []


def test_public_project_binding_is_critical(settings: Settings) -> None:
    project_iam = {
        "project_id": "p",
        "bindings": [{"role": "roles/editor", "members": ["allUsers"], "condition": None}],
        "audit_configs": [{"service": "x", "log_types": ["DATA_READ"]}],
    }
    findings = check_project_iam(project_iam, settings)
    public = by_rule(findings, "IAM-PROJ-PUBLIC-BINDING")
    assert len(public) == 1
    assert public[0].severity is Severity.CRITICAL
    assert public[0].remediation_commands == [
        'gcloud projects remove-iam-policy-binding p --member="allUsers" --role="roles/editor"'
    ]


def test_conditional_iam_admin_is_not_flagged_as_unconditional(settings: Settings) -> None:
    project_iam = {
        "project_id": "p",
        "bindings": [
            {
                "role": "roles/resourcemanager.projectIamAdmin",
                "members": ["group:break-glass@example.com"],
                "condition": {
                    "title": "ttl",
                    "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                },
            }
        ],
        "audit_configs": [{"service": "x", "log_types": ["DATA_READ"]}],
    }
    assert "IAM-PROJ-UNCONDITIONAL-IAM-ADMIN" not in rule_ids(
        check_project_iam(project_iam, settings)
    )


def test_actas_plus_execution_role_is_an_escalation_path(settings: Settings) -> None:
    project_iam = {
        "project_id": "p",
        "bindings": [
            {"role": "roles/iam.serviceAccountUser", "members": ["user:dev@example.com"]},
            {"role": "roles/run.admin", "members": ["user:dev@example.com"]},
            {"role": "roles/owner", "members": ["serviceAccount:god@p.iam.gserviceaccount.com"]},
        ],
    }
    service_accounts = {
        "service_accounts": [{"email": "god@p.iam.gserviceaccount.com", "user_managed_keys": []}]
    }
    findings = by_rule(
        check_attack_paths(project_iam, service_accounts, settings), "IAM-PATH-ACTAS-ESCALATION"
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert ThreatCategory.CRYPTOJACKING in finding.categories
    assert finding.evidence["reachable_privileged_service_accounts"] == [
        "god@p.iam.gserviceaccount.com"
    ]


def test_execution_role_without_actas_is_not_an_escalation_path(settings: Settings) -> None:
    project_iam = {
        "project_id": "p",
        "bindings": [{"role": "roles/run.admin", "members": ["user:dev@example.com"]}],
    }
    assert check_attack_paths(project_iam, {}, settings) == []


def test_hardened_bucket_is_clean(settings: Settings) -> None:
    gcs = {
        "buckets": [
            {
                "name": "hardened",
                "uniform_bucket_level_access": True,
                "public_access_prevention": "enforced",
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["group:app@example.com"]}
                ],
            }
        ]
    }
    assert check_gcs(gcs, settings) == []


def test_public_bucket_is_critical(settings: Settings) -> None:
    gcs = {
        "buckets": [
            {
                "name": "leaky",
                "uniform_bucket_level_access": True,
                "public_access_prevention": "enforced",
                "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
            }
        ]
    }
    findings = check_gcs(gcs, settings)
    assert rule_ids(findings) == {"GCS-PUBLIC-BUCKET"}
    assert findings[0].severity is Severity.CRITICAL


def test_full_inventory_detects_expected_rules(
    vulnerable_inventory: dict[str, Any], settings: Settings
) -> None:
    findings = analyze(vulnerable_inventory, settings)
    detected = rule_ids(findings)
    expected = {
        "IAM-PROJ-PUBLIC-BINDING",
        "IAM-PROJ-BASIC-ROLE",
        "IAM-PROJ-UNCONDITIONAL-IAM-ADMIN",
        "IAM-PROJ-BROAD-IMPERSONATION",
        "IAM-PROJ-EXTERNAL-PRINCIPAL",
        "IAM-PROJ-QUOTA-CONTROL",
        "IAM-PROJ-NO-DATA-ACCESS-LOGS",
        "IAM-PATH-ACTAS-ESCALATION",
        "IAM-SA-USER-MANAGED-KEY",
        "IAM-SA-DISABLED-WITH-ROLES",
        "IAM-SA-EXTERNAL-IMPERSONATION",
        "GCE-DEFAULT-SA-FULL-SCOPE",
        "GCE-EXTERNAL-IP",
        "GCE-OSLOGIN-DISABLED",
        "GCE-SERIAL-PORT-ENABLED",
        "GCE-GPU-WORKLOAD-REVIEW",
        "GCS-PUBLIC-BUCKET",
        "GCS-UBLA-DISABLED",
        "GCS-PAP-NOT-ENFORCED",
        "GCS-EXTERNAL-WRITE-ACCESS",
        "BQ-PUBLIC-DATASET",
        "BQ-DOMAIN-WIDE-ACCESS",
        "BQ-EXTERNAL-USER-ACCESS",
        "BQ-PROJECT-EDITORS-OWNER",
    }
    assert expected <= detected


def test_findings_are_sorted_by_severity_and_are_unique(
    vulnerable_inventory: dict[str, Any], settings: Settings
) -> None:
    findings = analyze(vulnerable_inventory, settings)
    assert [f.severity.rank for f in findings] == sorted(f.severity.rank for f in findings)
    keys = [
        (f.rule_id, f.resource, tuple(sorted(f.principals)), tuple(sorted(f.roles)))
        for f in findings
    ]
    assert len(keys) == len(set(keys))


def test_every_finding_is_serialisable_and_explained(
    vulnerable_inventory: dict[str, Any], settings: Settings
) -> None:
    for finding in analyze(vulnerable_inventory, settings):
        data = finding.to_dict()
        assert isinstance(data["severity"], str)
        assert data["explanation"] and data["remediation"]
        assert data["categories"]


def test_empty_inventory_yields_no_findings(settings: Settings) -> None:
    assert analyze({}, settings) == []
