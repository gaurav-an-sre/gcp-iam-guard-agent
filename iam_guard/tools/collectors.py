"""Read-only collector tools exposed to the ADK collection agents.

Every tool follows the same contract:

* it never mutates GCP state (read-only API calls only);
* it returns a small JSON-serialisable summary for the model;
* it stores the full inventory in session state so the deterministic rule engine
  can analyse it without the inventory passing through the model's context.

Set ``IAM_GUARD_FIXTURE=/path/to/inventory.json`` to run the whole workflow
against a recorded inventory instead of live APIs. This is what the unit tests
and the demo use.
"""

from __future__ import annotations

import json
import os
from typing import Any

from google.adk.tools import ToolContext
from google.api_core import exceptions as gcp_exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud import bigquery, compute_v1, iam_admin_v1, resourcemanager_v3, storage
from google.iam.v1 import iam_policy_pb2, options_pb2

from iam_guard.config import get_settings
from iam_guard.models import (
    STATE_BIGQUERY,
    STATE_COLLECTION_ERRORS,
    STATE_GCE,
    STATE_GCS,
    STATE_PROJECT_IAM,
    STATE_SERVICE_ACCOUNTS,
)

FIXTURE_ENV_VAR = "IAM_GUARD_FIXTURE"

#: Credential errors surface while building a client, API errors while calling it.
COLLECTION_ERRORS = (
    gcp_exceptions.GoogleAPIError,
    auth_exceptions.GoogleAuthError,
    OSError,
)


def _resolve_project(project_id: str) -> str:
    return project_id or get_settings().default_project_id


def _fixture(section: str) -> dict[str, Any] | None:
    path = os.environ.get(FIXTURE_ENV_VAR)
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle).get(section)


def _record(tool_context: ToolContext | None, key: str, value: dict[str, Any]) -> None:
    if tool_context is not None:
        tool_context.state[key] = value


def _record_error(tool_context: ToolContext | None, key: str, message: str) -> None:
    if tool_context is None:
        return
    errors = dict(tool_context.state.get(STATE_COLLECTION_ERRORS) or {})
    errors[key] = message
    tool_context.state[STATE_COLLECTION_ERRORS] = errors


def _failure(
    tool_context: ToolContext | None, key: str, error: Exception, hint: str
) -> dict[str, Any]:
    message = f"{type(error).__name__}: {error}"
    _record_error(tool_context, key, message)
    return {"status": "error", "error": message, "hint": hint}


def _load_fixture(
    section: str, tool_context: ToolContext | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Returns ``(inventory, failure)``; both are None when running against live APIs."""
    try:
        return _fixture(section), None
    except (OSError, ValueError) as error:
        return None, _failure(
            tool_context,
            section,
            error,
            f"Point {FIXTURE_ENV_VAR} at a readable JSON inventory file, or unset it "
            "to collect from Google Cloud.",
        )


def collect_project_iam_policy(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Fetches the allow policy and audit log configuration of a GCP project.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with the binding count, the roles seen and any public members.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return {"status": "error", "error": "No project_id supplied or configured."}

    inventory, failure = _load_fixture(STATE_PROJECT_IAM, tool_context)
    if failure is not None:
        return failure
    if inventory is None:
        try:
            client = resourcemanager_v3.ProjectsClient()
            policy = client.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(
                    resource=f"projects/{project_id}",
                    options=options_pb2.GetPolicyOptions(requested_policy_version=3),
                )
            )
        except COLLECTION_ERRORS as error:
            return _failure(
                tool_context,
                STATE_PROJECT_IAM,
                error,
                "Grant the agent roles/iam.securityReviewer on the project.",
            )
        inventory = {
            "project_id": project_id,
            "bindings": [
                {
                    "role": binding.role,
                    "members": list(binding.members),
                    "condition": (
                        {
                            "title": binding.condition.title,
                            "expression": binding.condition.expression,
                        }
                        if binding.condition.expression
                        else None
                    ),
                }
                for binding in policy.bindings
            ],
            "audit_configs": [
                {
                    "service": config.service,
                    "log_types": [log.log_type for log in config.audit_log_configs],
                }
                for config in policy.audit_configs
            ],
        }

    _record(tool_context, STATE_PROJECT_IAM, inventory)
    bindings = inventory.get("bindings", [])
    return {
        "status": "ok",
        "project_id": project_id,
        "binding_count": len(bindings),
        "distinct_roles": sorted({b.get("role", "") for b in bindings}),
        "public_members": sorted(
            {
                member
                for binding in bindings
                for member in binding.get("members", [])
                if member in {"allUsers", "allAuthenticatedUsers"}
            }
        ),
        "audit_configs_present": bool(inventory.get("audit_configs")),
    }


def collect_service_accounts(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists service accounts with their user-managed keys and resource policies.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with the account count and how many hold exported keys.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return {"status": "error", "error": "No project_id supplied or configured."}

    inventory, failure = _load_fixture(STATE_SERVICE_ACCOUNTS, tool_context)
    if failure is not None:
        return failure
    if inventory is None:
        try:
            client = iam_admin_v1.IAMClient()
            accounts = []
            for account in client.list_service_accounts(name=f"projects/{project_id}"):
                keys = client.list_service_account_keys(
                    request=iam_admin_v1.ListServiceAccountKeysRequest(
                        name=account.name,
                        key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
                    )
                )
                policy = client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(resource=account.name)
                )
                accounts.append(
                    {
                        "email": account.email,
                        "display_name": account.display_name,
                        "disabled": account.disabled,
                        "user_managed_keys": [
                            {
                                "key_id": key.name.rsplit("/", 1)[-1],
                                "valid_after": key.valid_after_time.rfc3339()
                                if key.valid_after_time
                                else "",
                            }
                            for key in keys.keys
                        ],
                        "iam_policy_bindings": [
                            {"role": binding.role, "members": list(binding.members)}
                            for binding in policy.bindings
                        ],
                    }
                )
        except COLLECTION_ERRORS as error:
            return _failure(
                tool_context,
                STATE_SERVICE_ACCOUNTS,
                error,
                "Grant the agent roles/iam.securityReviewer and enable iam.googleapis.com.",
            )
        inventory = {"project_id": project_id, "service_accounts": accounts}

    _record(tool_context, STATE_SERVICE_ACCOUNTS, inventory)
    accounts = inventory.get("service_accounts", [])
    return {
        "status": "ok",
        "project_id": project_id,
        "service_account_count": len(accounts),
        "accounts_with_user_managed_keys": [
            account.get("email") for account in accounts if account.get("user_managed_keys")
        ],
    }


def collect_compute_inventory(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists Compute Engine instances with their identities and exposure settings.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with instance counts, attached identities and internet exposure.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return {"status": "error", "error": "No project_id supplied or configured."}
    settings = get_settings()

    inventory, failure = _load_fixture(STATE_GCE, tool_context)
    if failure is not None:
        return failure
    if inventory is None:
        try:
            instances_client = compute_v1.InstancesClient()
            projects_client = compute_v1.ProjectsClient()
            project_info = projects_client.get(project=project_id)
            project_metadata = {
                item.key: item.value for item in project_info.common_instance_metadata.items
            }
            instances: list[dict[str, Any]] = []
            for zone, scoped in instances_client.aggregated_list(project=project_id):
                for instance in scoped.instances:
                    if len(instances) >= settings.max_instances:
                        break
                    metadata = {item.key: item.value for item in instance.metadata.items}
                    instances.append(
                        {
                            "name": instance.name,
                            "zone": zone.rsplit("/", 1)[-1],
                            "status": instance.status,
                            "machine_type": instance.machine_type.rsplit("/", 1)[-1],
                            "gpu_count": sum(
                                accelerator.accelerator_count
                                for accelerator in instance.guest_accelerators
                            ),
                            "can_ip_forward": instance.can_ip_forward,
                            "shielded_vm": bool(
                                instance.shielded_instance_config.enable_secure_boot
                            ),
                            "service_accounts": [
                                {"email": sa.email, "scopes": list(sa.scopes)}
                                for sa in instance.service_accounts
                            ],
                            "external_ips": [
                                config.nat_i_p
                                for interface in instance.network_interfaces
                                for config in interface.access_configs
                                if config.nat_i_p
                            ],
                            "metadata": metadata,
                            "block_project_ssh_keys": str(
                                metadata.get("block-project-ssh-keys", "false")
                            ).lower()
                            == "true",
                            "serial_port_enabled": str(
                                metadata.get("serial-port-enable", "false")
                            ).lower()
                            in {"true", "1"},
                        }
                    )
        except COLLECTION_ERRORS as error:
            return _failure(
                tool_context,
                STATE_GCE,
                error,
                "Grant the agent roles/compute.viewer and enable compute.googleapis.com.",
            )
        inventory = {
            "project_id": project_id,
            "project_metadata": project_metadata,
            "instances": instances,
        }

    _record(tool_context, STATE_GCE, inventory)
    instances = inventory.get("instances", [])
    return {
        "status": "ok",
        "project_id": project_id,
        "instance_count": len(instances),
        "internet_facing_instances": [
            instance.get("name") for instance in instances if instance.get("external_ips")
        ],
        "attached_service_accounts": sorted(
            {
                sa.get("email", "")
                for instance in instances
                for sa in instance.get("service_accounts", [])
            }
        ),
        "oslogin_enforced": str(
            inventory.get("project_metadata", {}).get("enable-oslogin", "")
        ).upper()
        in {"TRUE", "1"},
    }


def collect_storage_inventory(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists Cloud Storage buckets with their IAM policies and exposure controls.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with bucket counts and which buckets are publicly readable.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return {"status": "error", "error": "No project_id supplied or configured."}
    settings = get_settings()

    inventory, failure = _load_fixture(STATE_GCS, tool_context)
    if failure is not None:
        return failure
    if inventory is None:
        try:
            client = storage.Client(project=project_id)
            buckets: list[dict[str, Any]] = []
            for bucket in client.list_buckets(max_results=settings.max_buckets):
                policy = bucket.get_iam_policy(requested_policy_version=3)
                iam_configuration = bucket.iam_configuration
                buckets.append(
                    {
                        "name": bucket.name,
                        "location": bucket.location,
                        "uniform_bucket_level_access": bool(
                            iam_configuration.uniform_bucket_level_access_enabled
                        ),
                        "public_access_prevention": iam_configuration.public_access_prevention,
                        "versioning_enabled": bool(bucket.versioning_enabled),
                        "bindings": [
                            {"role": binding["role"], "members": sorted(binding["members"])}
                            for binding in policy.bindings
                        ],
                    }
                )
        except COLLECTION_ERRORS as error:
            return _failure(
                tool_context,
                STATE_GCS,
                error,
                "Grant the agent roles/storage.admin or roles/iam.securityReviewer.",
            )
        inventory = {"project_id": project_id, "buckets": buckets}

    _record(tool_context, STATE_GCS, inventory)
    buckets = inventory.get("buckets", [])
    public = [
        bucket.get("name")
        for bucket in buckets
        for binding in bucket.get("bindings", [])
        if {"allUsers", "allAuthenticatedUsers"} & set(binding.get("members", []))
    ]
    return {
        "status": "ok",
        "project_id": project_id,
        "bucket_count": len(buckets),
        "public_buckets": sorted(set(public)),
    }


def collect_bigquery_inventory(
    project_id: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Lists BigQuery datasets with their access entries.

    Args:
        project_id: Project to inspect. Defaults to the configured project.

    Returns:
        A summary with dataset counts and which datasets are broadly shared.
    """
    project_id = _resolve_project(project_id)
    if not project_id:
        return {"status": "error", "error": "No project_id supplied or configured."}
    settings = get_settings()

    inventory, failure = _load_fixture(STATE_BIGQUERY, tool_context)
    if failure is not None:
        return failure
    if inventory is None:
        try:
            client = bigquery.Client(project=project_id)
            datasets: list[dict[str, Any]] = []
            for listed in client.list_datasets(max_results=settings.max_datasets):
                dataset = client.get_dataset(listed.reference)
                datasets.append(
                    {
                        "dataset_id": dataset.dataset_id,
                        "location": dataset.location,
                        "access_entries": [
                            {
                                "role": entry.role,
                                "entity_type": entry.entity_type,
                                "entity_id": entry.entity_id,
                            }
                            for entry in dataset.access_entries
                        ],
                    }
                )
        except COLLECTION_ERRORS as error:
            return _failure(
                tool_context,
                STATE_BIGQUERY,
                error,
                "Grant the agent roles/bigquery.metadataViewer and enable bigquery.googleapis.com.",
            )
        inventory = {"project_id": project_id, "datasets": datasets}

    _record(tool_context, STATE_BIGQUERY, inventory)
    datasets = inventory.get("datasets", [])
    broadly_shared = [
        dataset.get("dataset_id")
        for dataset in datasets
        for entry in dataset.get("access_entries", [])
        if entry.get("entity_type") == "domain"
        or entry.get("entity_id") in {"allUsers", "allAuthenticatedUsers"}
    ]
    return {
        "status": "ok",
        "project_id": project_id,
        "dataset_count": len(datasets),
        "broadly_shared_datasets": sorted(set(broadly_shared)),
    }


COLLECTOR_TOOLS = [
    collect_project_iam_policy,
    collect_service_accounts,
    collect_compute_inventory,
    collect_storage_inventory,
    collect_bigquery_inventory,
]
