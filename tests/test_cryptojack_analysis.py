"""Adversarial tests for the deterministic cryptojacking rule engine.

The engine is the source of truth for the whole workflow: the report stage only
explains what it decides. So these tests pin the two invariants that keep it honest
(only a threat-detection product yields CONFIRMED; preventive gaps never imply active
mining) and prove it survives the malformed input real APIs and fixtures produce.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cryptojack_guard.analysis import analyze
from cryptojack_guard.config import Settings
from cryptojack_guard.models import (
    STATE_BUDGETS,
    STATE_MONITORING,
    STATE_ORG_POLICIES,
    STATE_QUOTAS,
    STATE_SCC_FINDINGS,
    Confidence,
    Signal,
    SignalKind,
    summarize,
    verdict,
)
from iam_guard.models import STATE_GCE, Severity


def rules(signals: list[Signal]) -> set[str]:
    return {signal.rule_id for signal in signals}


def by_rule(signals: list[Signal], rule_id: str) -> list[Signal]:
    return [signal for signal in signals if signal.rule_id == rule_id]


def only(signals: list[Signal], rule_id: str) -> Signal:
    matches = by_rule(signals, rule_id)
    assert len(matches) == 1, f"expected exactly one {rule_id}, got {len(matches)}"
    return matches[0]


@pytest.fixture
def settings() -> Settings:
    """Explicit thresholds so tests never depend on the ambient environment."""
    return Settings(
        model="test",
        default_project_id="demo-prod-1234",
        organization_id="",
        billing_account_id="",
        cpu_threshold=0.9,
        cpu_sustained_minutes=120,
        gpu_threshold=0.8,
        quota_usage_threshold=0.8,
        lookback_hours=24,
        max_instances=500,
        max_findings=200,
    )


# --------------------------------------------------------------------------- #
# Nothing in, nothing out
# --------------------------------------------------------------------------- #


def test_empty_state_produces_no_signals(settings: Settings) -> None:
    signals = analyze({}, settings)

    assert signals == []
    assert verdict(signals) == "clean"


def test_quiet_project_produces_no_detections(settings: Settings) -> None:
    """A busy-but-explained project must not be accused of mining."""
    state = {
        STATE_SCC_FINDINGS: {"project_id": "p", "findings": []},
        STATE_MONITORING: {
            "project_id": "p",
            "cpu_threshold": 0.9,
            "instances": [
                {
                    "instance": "api-1",
                    "zone": "us-central1-b",
                    "mean_cpu_utilization": 0.35,
                    "minutes_above_cpu_threshold": 0,
                },
                # Briefly pinned, but nowhere near the sustained window.
                {
                    "instance": "ci-runner-3",
                    "zone": "us-central1-b",
                    "mean_cpu_utilization": 0.95,
                    "minutes_above_cpu_threshold": 30,
                },
            ],
        },
        STATE_QUOTAS: {
            "project_id": "p",
            "regions": [
                {
                    "region": "us-central1",
                    "quotas": [{"metric": "CPUS", "limit": 240.0, "usage": 40.0}],
                }
            ],
        },
        STATE_BUDGETS: {
            "project_id": "p",
            "budgets": [
                {
                    "display_name": "whole account",
                    "projects": [],
                    "notifications_configured": True,
                }
            ],
        },
        STATE_ORG_POLICIES: {
            "project_id": "p",
            "constraints": {
                name: {"enforced": True, "detail": "enforced"}
                for name in (
                    "constraints/iam.disableServiceAccountKeyCreation",
                    "constraints/compute.vmExternalIpAccess",
                    "constraints/compute.requireOsLogin",
                    "constraints/compute.disableSerialPortAccess",
                    "constraints/compute.disableNestedVirtualization",
                )
            },
        },
        STATE_GCE: {
            "project_id": "p",
            "instances": [{"name": "api-1", "zone": "us-central1-b", "external_ips": []}],
        },
    }

    signals = analyze(state, settings)

    assert signals == []
    assert verdict(signals) == "clean"


def test_enforced_policies_and_covering_budget_are_not_gaps(settings: Settings) -> None:
    """An account-wide budget with no project filter still covers the project."""
    state = {
        STATE_BUDGETS: {
            "project_id": "demo",
            "budgets": [{"display_name": "account wide", "notifications_configured": True}],
        },
    }

    assert analyze(state, settings) == []


# --------------------------------------------------------------------------- #
# SCC detections
# --------------------------------------------------------------------------- #


def test_scc_mining_finding_is_the_only_route_to_confirmed(settings: Settings) -> None:
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "name": "findings/f1",
                    "category": "Execution: Cryptocurrency Mining YARA Rule",
                    "severity": "HIGH",
                    "finding_class": "THREAT",
                    "resource_name": (
                        "//compute.googleapis.com/projects/demo/zones/"
                        "us-central1-a/instances/miner-1"
                    ),
                }
            ],
        }
    }

    signal = only(analyze(state, settings), "CJ-SCC-MINING-DETECTION")

    assert signal.confidence is Confidence.CONFIRMED
    # SCC says HIGH, but a named miner is always an incident.
    assert signal.severity is Severity.CRITICAL
    assert signal.kind is SignalKind.DETECTION
    assert verdict(analyze(state, settings)) == "confirmed_mining"


def test_mining_findings_on_one_instance_merge_into_one_incident(settings: Settings) -> None:
    resource = "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/miner-1"
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "name": "findings/f1",
                    "category": "Execution: Cryptocurrency Mining Hash Match",
                    "finding_class": "THREAT",
                    "resource_name": resource,
                },
                {
                    "name": "findings/f2",
                    "category": "Malware: Cryptomining Bad Domain",
                    "finding_class": "THREAT",
                    "resource_name": resource,
                },
            ],
        }
    }

    signal = only(analyze(state, settings), "CJ-SCC-MINING-DETECTION")

    # Deduplication must not lose the second finding's evidence.
    assert len(signal.evidence["findings"]) == 2
    assert signal.evidence["categories"] == [
        "Execution: Cryptocurrency Mining Hash Match",
        "Malware: Cryptomining Bad Domain",
    ]


def test_non_mining_threat_is_context_not_confirmation(settings: Settings) -> None:
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "category": "Persistence: IAM Anomalous Grant",
                    "severity": "MEDIUM",
                    "finding_class": "THREAT",
                    "resource_name": "//cloudresourcemanager.googleapis.com/projects/demo",
                }
            ],
        }
    }

    signals = analyze(state, settings)
    signal = only(signals, "CJ-SCC-THREAT-FINDING")

    assert signal.confidence is Confidence.MEDIUM
    assert signal.severity is Severity.MEDIUM
    assert verdict(signals) == "suspected_mining"


def test_misconfiguration_findings_are_ignored(settings: Settings) -> None:
    """IAM Guard owns misconfiguration; this agent only reads threat classes."""
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "category": "Public bucket ACL",
                    "severity": "HIGH",
                    "finding_class": "MISCONFIGURATION",
                    "resource_name": "//storage.googleapis.com/demo-public",
                }
            ],
        }
    }

    assert analyze(state, settings) == []


def test_unknown_scc_severity_falls_back_to_medium(settings: Settings) -> None:
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "category": "Persistence: New Geography",
                    "severity": "SEVERITY_UNSPECIFIED",
                    "finding_class": "THREAT",
                    "resource_name": "//cloudresourcemanager.googleapis.com/projects/demo",
                }
            ],
        }
    }

    assert only(analyze(state, settings), "CJ-SCC-THREAT-FINDING").severity is Severity.MEDIUM


# --------------------------------------------------------------------------- #
# Utilisation detections
# --------------------------------------------------------------------------- #


def _monitoring(instance: dict[str, Any]) -> dict[str, Any]:
    return {
        STATE_MONITORING: {
            "project_id": "demo",
            "cpu_threshold": 0.9,
            "instances": [instance],
        }
    }


def test_sustained_cpu_is_medium_confidence(settings: Settings) -> None:
    signals = analyze(
        _monitoring(
            {
                "instance": "worker-1",
                "zone": "us-central1-a",
                "mean_cpu_utilization": 0.98,
                "max_cpu_utilization": 1.0,
                "minutes_above_cpu_threshold": 900,
            }
        ),
        settings,
    )

    signal = only(signals, "CJ-MON-SUSTAINED-CPU")
    assert signal.confidence is Confidence.MEDIUM
    assert signal.evidence["minutes_above_threshold"] == 900
    assert verdict(signals) == "suspected_mining"


def test_high_cpu_that_is_not_sustained_is_not_flagged(settings: Settings) -> None:
    """A short burst is a batch job, not a miner: this is the false-positive guard."""
    signals = analyze(
        _monitoring(
            {
                "instance": "worker-1",
                "zone": "us-central1-a",
                "mean_cpu_utilization": 0.97,
                "minutes_above_cpu_threshold": 60,
            }
        ),
        settings,
    )

    assert signals == []


def test_gpu_only_saturation_stays_low_confidence(settings: Settings) -> None:
    signals = analyze(
        _monitoring(
            {
                "instance": "ml-train-1",
                "zone": "us-central1-b",
                "mean_cpu_utilization": 0.4,
                "minutes_above_cpu_threshold": 0,
                "mean_gpu_utilization": 0.9,
            }
        ),
        settings,
    )

    signal = only(signals, "CJ-MON-GPU-SATURATION")
    assert signal.confidence is Confidence.LOW
    assert rules(signals) == {"CJ-MON-GPU-SATURATION"}


def test_thresholds_are_configurable(settings: Settings) -> None:
    """Operators tune thresholds instead of patching rules."""
    instance = {
        "instance": "render-1",
        "zone": "us-central1-a",
        "mean_cpu_utilization": 0.93,
        "minutes_above_cpu_threshold": 600,
    }
    tolerant = Settings(**{**settings.__dict__, "cpu_threshold": 0.99})

    assert by_rule(analyze(_monitoring(instance), settings), "CJ-MON-SUSTAINED-CPU")
    # The fixture's own recorded threshold takes precedence when present, so the
    # tolerant setting only applies to state that does not carry one.
    without_recorded_threshold = {STATE_MONITORING: {"project_id": "demo", "instances": [instance]}}
    assert not by_rule(analyze(without_recorded_threshold, tolerant), "CJ-MON-SUSTAINED-CPU")


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #


def test_scc_plus_saturation_correlates_to_confirmed(settings: Settings) -> None:
    state = {
        STATE_SCC_FINDINGS: {
            "project_id": "demo",
            "findings": [
                {
                    "category": "Execution: Cryptocurrency Mining Hash Match",
                    "finding_class": "THREAT",
                    "resource_name": (
                        "//compute.googleapis.com/projects/demo/zones/"
                        "us-central1-a/instances/batch-worker-7"
                    ),
                }
            ],
        },
        STATE_MONITORING: {
            "project_id": "demo",
            "cpu_threshold": 0.9,
            "instances": [
                {
                    "instance": "batch-worker-7",
                    "zone": "us-central1-a",
                    "mean_cpu_utilization": 0.99,
                    "minutes_above_cpu_threshold": 1400,
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [
                {
                    "name": "batch-worker-7",
                    "zone": "us-central1-a",
                    "external_ips": ["203.0.113.44"],
                    "service_accounts": [
                        {
                            "email": "default-compute@demo.iam.gserviceaccount.com",
                            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                        }
                    ],
                }
            ],
        },
    }

    signals = analyze(state, settings)
    correlated = only(signals, "CJ-CORR-CONFIRMED-MINER")

    assert correlated.confidence is Confidence.CONFIRMED
    # The SCC-named instance takes the confirmed path, not the HIGH heuristic one.
    assert not by_rule(signals, "CJ-CORR-SATURATED-EXPOSED-PRIVILEGED")
    assert any("disks snapshot" in command for command in correlated.advisory_commands)


def test_saturated_exposed_privileged_vm_is_high_not_confirmed(settings: Settings) -> None:
    """The full cryptojacking shape without a detection product tops out at HIGH."""
    state = {
        STATE_MONITORING: {
            "project_id": "demo",
            "cpu_threshold": 0.9,
            "instances": [
                {
                    "instance": "unknown-1",
                    "zone": "us-central1-a",
                    "mean_cpu_utilization": 0.99,
                    "minutes_above_cpu_threshold": 1400,
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [
                {
                    "name": "unknown-1",
                    "zone": "us-central1-a",
                    "machine_type": "n1-standard-16",
                    "external_ips": ["203.0.113.7"],
                    "service_accounts": [
                        {
                            "email": "default-compute@demo.iam.gserviceaccount.com",
                            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                        }
                    ],
                }
            ],
        },
    }

    signals = analyze(state, settings)
    signal = only(signals, "CJ-CORR-SATURATED-EXPOSED-PRIVILEGED")

    assert signal.confidence is Confidence.HIGH
    assert verdict(signals) == "likely_mining"
    assert any("delete-access-config" in command for command in signal.advisory_commands)


def test_saturated_but_private_and_unprivileged_vm_does_not_correlate(
    settings: Settings,
) -> None:
    state = {
        STATE_MONITORING: {
            "project_id": "demo",
            "cpu_threshold": 0.9,
            "instances": [
                {
                    "instance": "render-node-2",
                    "zone": "us-central1-b",
                    "mean_cpu_utilization": 0.96,
                    "minutes_above_cpu_threshold": 900,
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [
                {
                    "name": "render-node-2",
                    "zone": "us-central1-b",
                    "external_ips": [],
                    "service_accounts": [
                        {
                            "email": "render@demo.iam.gserviceaccount.com",
                            "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"],
                        }
                    ],
                }
            ],
        },
    }

    assert rules(analyze(state, settings)) == {"CJ-MON-SUSTAINED-CPU"}


def test_monitoring_instance_absent_from_inventory_is_not_correlated(
    settings: Settings,
) -> None:
    """A name mismatch must not fabricate a correlation."""
    state = {
        STATE_MONITORING: {
            "project_id": "demo",
            "cpu_threshold": 0.9,
            "instances": [
                {
                    "instance": "4471100022330011",
                    "zone": "us-central1-a",
                    "mean_cpu_utilization": 0.99,
                    "minutes_above_cpu_threshold": 1400,
                }
            ],
        },
        STATE_GCE: {"project_id": "demo", "instances": [{"name": "batch-worker-7"}]},
    }

    assert rules(analyze(state, settings)) == {"CJ-MON-SUSTAINED-CPU"}


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


def test_capacity_used_in_a_region_with_no_instances(settings: Settings) -> None:
    state = {
        STATE_QUOTAS: {
            "project_id": "demo",
            "regions": [
                {
                    "region": "asia-southeast1",
                    "quotas": [{"metric": "CPUS", "limit": 120.0, "usage": 12.0}],
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [{"name": "api-1", "zone": "us-central1-b"}],
        },
    }

    signal = only(analyze(state, settings), "CJ-QUOTA-UNEXPECTED-REGION")

    # Low ratio, but the region itself is the signal.
    assert signal.evidence["utilization"] == 0.1
    assert signal.confidence is Confidence.MEDIUM
    assert signal.evidence["regions_with_inventory"] == ["us-central1"]


def test_near_limit_capacity_in_an_expected_region_is_low(settings: Settings) -> None:
    state = {
        STATE_QUOTAS: {
            "project_id": "demo",
            "regions": [
                {
                    "region": "us-central1",
                    "quotas": [
                        {"metric": "CPUS", "limit": 240.0, "usage": 228.0},
                        {"metric": "NVIDIA_T4_GPUS", "limit": 8.0, "usage": 2.0},
                    ],
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [{"name": "api-1", "zone": "us-central1-b"}],
        },
    }

    signal = only(analyze(state, settings), "CJ-QUOTA-NEAR-LIMIT")

    assert signal.confidence is Confidence.LOW
    assert signal.evidence["metric"] == "CPUS"


def test_unread_inventory_suppresses_the_unexpected_region_rule(settings: Settings) -> None:
    """Without an inventory, every region would look unexpected; that would be noise."""
    state = {
        STATE_QUOTAS: {
            "project_id": "demo",
            "regions": [
                {
                    "region": "asia-southeast1",
                    "quotas": [{"metric": "CPUS", "limit": 120.0, "usage": 12.0}],
                }
            ],
        },
    }

    assert analyze(state, settings) == []


def test_unused_quota_is_not_a_signal(settings: Settings) -> None:
    state = {
        STATE_QUOTAS: {
            "project_id": "demo",
            "regions": [
                {
                    "region": "us-central1",
                    "quotas": [{"metric": "CPUS", "limit": 200.0, "usage": 0.0}],
                }
            ],
        },
        STATE_GCE: {
            "project_id": "demo",
            "instances": [{"name": "api-1", "zone": "us-central1-b"}],
        },
    }

    assert analyze(state, settings) == []


def test_zero_limit_quota_does_not_divide_by_zero(settings: Settings) -> None:
    state = {
        STATE_QUOTAS: {
            "project_id": "demo",
            "regions": [
                {
                    "region": "us-central1",
                    "quotas": [{"metric": "CPUS", "limit": 0.0, "usage": 4.0}],
                }
            ],
        },
        STATE_GCE: {"project_id": "demo", "instances": [{"name": "a", "zone": "us-central1-b"}]},
    }

    assert analyze(state, settings) == []


# --------------------------------------------------------------------------- #
# Preventive gaps
# --------------------------------------------------------------------------- #


def test_budget_covering_another_project_is_no_coverage(settings: Settings) -> None:
    state = {
        STATE_BUDGETS: {
            "project_id": "demo-prod-1234",
            "budgets": [
                {
                    "display_name": "sandbox only",
                    "projects": ["projects/demo-sandbox-9999"],
                    "notifications_configured": True,
                }
            ],
        }
    }

    signal = only(analyze(state, settings), "CJ-BILLING-NO-BUDGET")

    assert signal.kind is SignalKind.PREVENTIVE
    assert signal.confidence is Confidence.LOW
    assert signal.severity is Severity.HIGH


def test_covering_budget_without_notifications_is_reported(settings: Settings) -> None:
    state = {
        STATE_BUDGETS: {
            "project_id": "demo-prod-1234",
            "budgets": [
                {
                    "display_name": "silent budget",
                    "projects": ["projects/demo-prod-1234"],
                    "notifications_configured": False,
                }
            ],
        }
    }

    signals = analyze(state, settings)

    assert rules(signals) == {"CJ-BILLING-BUDGET-WITHOUT-ALERTS"}
    assert verdict(signals) == "no_detections_preventive_gaps"


def test_unreadable_budgets_are_not_reported_as_missing(settings: Settings) -> None:
    """A collector failure leaves no state; absence of data is not absence of budgets."""
    assert analyze({}, settings) == []


def test_unenforced_constraints_become_preventive_gaps(settings: Settings) -> None:
    state = {
        STATE_ORG_POLICIES: {
            "project_id": "demo",
            "constraints": {
                "constraints/iam.disableServiceAccountKeyCreation": {"enforced": False},
                "constraints/compute.requireOsLogin": {"enforced": True},
            },
        }
    }

    signals = analyze(state, settings)

    assert rules(signals) == {"CJ-POLICY-IAM-DISABLESERVICEACCOUNTKEYCREATION"}
    assert signals[0].severity is Severity.HIGH
    assert signals[0].kind is SignalKind.PREVENTIVE


def test_unreadable_constraint_is_skipped_not_guessed(settings: Settings) -> None:
    state = {
        STATE_ORG_POLICIES: {
            "project_id": "demo",
            "constraints": {"constraints/compute.requireOsLogin": None},
        }
    }

    assert analyze(state, settings) == []


def test_iam_preconditions_are_preventive_and_low_confidence(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    signals = analyze(cryptojacked_signals, settings)
    iam_signals = [signal for signal in signals if signal.source == "iam"]

    assert iam_signals
    for signal in iam_signals:
        assert signal.confidence is Confidence.LOW
        assert signal.kind is SignalKind.PREVENTIVE
        assert signal.rule_id.startswith("CJ-IAM-")
        assert signal.evidence["iam_guard_rule"]


def test_preventive_gaps_alone_never_imply_mining(settings: Settings) -> None:
    state = {
        STATE_BUDGETS: {"project_id": "demo", "budgets": []},
        STATE_ORG_POLICIES: {
            "project_id": "demo",
            "constraints": {
                "constraints/iam.disableServiceAccountKeyCreation": {"enforced": False},
                "constraints/compute.vmExternalIpAccess": {"enforced": False},
            },
        },
    }

    signals = analyze(state, settings)

    assert all(signal.kind is SignalKind.PREVENTIVE for signal in signals)
    assert verdict(signals) == "no_detections_preventive_gaps"


# --------------------------------------------------------------------------- #
# Robustness against malformed input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "state",
    [
        {STATE_SCC_FINDINGS: None},
        {STATE_SCC_FINDINGS: {"findings": None}},
        {STATE_SCC_FINDINGS: {"findings": ["not-a-dict", None]}},
        {STATE_SCC_FINDINGS: {"findings": [{"category": None}]}},
        {STATE_SCC_FINDINGS: {"findings": [{"category": 42, "finding_class": 7}]}},
        {STATE_MONITORING: {"instances": None}},
        {STATE_MONITORING: {"instances": [{"instance": None}]}},
        {STATE_MONITORING: {"cpu_threshold": "high", "instances": [{"instance": "a"}]}},
        {
            STATE_MONITORING: {
                "instances": [
                    {
                        "instance": "a",
                        "mean_cpu_utilization": None,
                        "minutes_above_cpu_threshold": "many",
                    }
                ]
            }
        },
        {STATE_QUOTAS: {"regions": None}},
        {STATE_QUOTAS: {"regions": [{"region": "us-central1", "quotas": None}]}},
        {
            STATE_QUOTAS: {
                "regions": [{"region": "us-central1", "quotas": [{"metric": None, "limit": "x"}]}]
            }
        },
        {STATE_BUDGETS: {"budgets": None}},
        {STATE_BUDGETS: {"budgets": [{"projects": None}]}},
        {STATE_BUDGETS: {"budgets": [{"projects": [None, 3]}]}},
        {STATE_ORG_POLICIES: {"constraints": None}},
        {STATE_ORG_POLICIES: {"constraints": "unavailable"}},
        {STATE_GCE: {"instances": None}},
        {STATE_GCE: {"instances": [{"name": None, "external_ips": None}]}},
        {
            STATE_MONITORING: {
                "cpu_threshold": 0.9,
                "instances": [
                    {
                        "instance": "a",
                        "mean_cpu_utilization": 0.99,
                        "minutes_above_cpu_threshold": 900,
                    }
                ],
            },
            STATE_GCE: {"instances": [{"name": "a", "service_accounts": None}]},
        },
    ],
)
def test_malformed_state_does_not_crash(state: dict[str, Any], settings: Settings) -> None:
    """Fixtures and JSON APIs both produce nulls; the engine must degrade, not raise."""
    signals = analyze(state, settings)

    assert isinstance(signals, list)
    assert all(isinstance(signal, Signal) for signal in signals)


# --------------------------------------------------------------------------- #
# Output contract
# --------------------------------------------------------------------------- #


def test_recorded_cryptojacked_project_is_confirmed(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    signals = analyze(cryptojacked_signals, settings)
    summary = summarize(signals)

    assert summary["verdict"] == "confirmed_mining"
    assert summary["by_confidence"]["CONFIRMED"] == 2
    assert {
        "CJ-SCC-MINING-DETECTION",
        "CJ-CORR-CONFIRMED-MINER",
        "CJ-SCC-THREAT-FINDING",
        "CJ-MON-SUSTAINED-CPU",
        "CJ-MON-GPU-SATURATION",
        "CJ-QUOTA-UNEXPECTED-REGION",
        "CJ-QUOTA-NEAR-LIMIT",
        "CJ-BILLING-NO-BUDGET",
    } <= rules(signals)
    assert summary["cryptojacking_risk_score"] == 100


def test_output_is_ordered_stable_and_serialisable(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    first = analyze(cryptojacked_signals, settings)
    second = analyze(cryptojacked_signals, settings)

    assert [s.to_dict() for s in first] == [s.to_dict() for s in second]
    ranks = [(s.confidence.rank, s.severity.rank) for s in first]
    assert ranks == sorted(ranks)
    json.dumps([signal.to_dict() for signal in first])


def test_no_duplicate_rule_and_resource_pairs(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    signals = analyze(cryptojacked_signals, settings)
    keys = [(signal.rule_id, signal.resource) for signal in signals]

    assert len(keys) == len(set(keys))


def test_every_detection_explains_the_innocent_reading(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    """Weak signals must not read as accusations, or operators stop trusting the agent."""
    for signal in analyze(cryptojacked_signals, settings):
        assert signal.explanation and signal.investigation and signal.remediation
        if signal.confidence in {Confidence.LOW, Confidence.MEDIUM}:
            assert signal.investigation, signal.rule_id


def test_advisory_commands_are_read_only_or_clearly_destructive_but_never_run(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    """Commands are strings for a human. Anything mutating must be flagged in-line."""
    mutating = ("instances stop", "delete-access-config", "budgets create", "budgets update")
    for signal in analyze(cryptojacked_signals, settings):
        for command in signal.advisory_commands:
            assert isinstance(command, str)
            if any(marker in command for marker in mutating):
                assert command.startswith("gcloud") or command.startswith("#")


def test_confirmed_detections_lead_with_evidence_preservation(
    cryptojacked_signals: dict[str, Any], settings: Settings, corporate_settings
) -> None:
    """Snapshot before stop, always: stopping first destroys the investigation."""
    for signal in analyze(cryptojacked_signals, settings):
        commands = signal.advisory_commands
        stops = [i for i, c in enumerate(commands) if "instances stop" in c]
        snapshots = [i for i, c in enumerate(commands) if "disks snapshot" in c]
        if stops:
            assert snapshots and min(snapshots) < min(stops), signal.rule_id
