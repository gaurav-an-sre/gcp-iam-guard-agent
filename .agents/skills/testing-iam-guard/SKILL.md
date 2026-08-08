---
name: testing-iam-guard
description: How to run and adversarially test the IAM Guard GCP IAM audit agent offline (rule engine, collectors, CLI) without GCP or Gemini credentials.
---

# Testing IAM Guard offline

The whole product is testable with **zero GCP and zero model credentials**. Anything
that touches a live model (`scripts/run_local.py --project X`, `deployment/*` beyond
`--help`) will fail with `google.auth.exceptions.DefaultCredentialsError` — that is
expected, do not chase credentials for it.

## Environment

- Interpreter: `/home/ubuntu/venv-adk/bin/python`, tests `/home/ubuntu/venv-adk/bin/pytest`.
- **The package must be installed into the venv or `scripts/run_local.py` dies with
  `ModuleNotFoundError: No module named 'iam_guard'`.** Fix:
  `/home/ubuntu/venv-adk/bin/pip install -e . --no-deps` (or the full
  `pip install -e ".[dev,deploy]"`). `pytest` passes even without it (rootdir insertion),
  so a green test run does **not** prove the CLI works — always run the CLI explicitly.
- `deployment/deploy.py` imports `vertexai` at module import time, so even `--help`
  needs the `[deploy]` extra (`pip install "google-cloud-aiplatform[agent_engines,adk]>=1.112"`).
  Without it you get a `ModuleNotFoundError` traceback rather than usage text.
- Noise: every command prints `FutureWarning` lines about Python 3.10 from
  `google.api_core`. Filter with `2>&1 | grep -viE "futurewarning|warnings.warn"`.

## Primary offline entry points

```bash
# rule engine only, no model, no creds
python scripts/run_local.py --rules-only examples/vulnerable_inventory.json

# drive the ADK collector tools from a recorded inventory
IAM_GUARD_FIXTURE=/path/to/inventory.json python -c "..."
```

Fixture JSON top-level keys must be exactly the state keys in `iam_guard/models.py`:
`project_iam`, `service_accounts`, `gce_inventory`, `gcs_inventory`, `bigquery_inventory`.

## Driving collectors without ADK

`ToolContext` can be replaced by any object with a `.state` dict:

```python
class Ctx:
    def __init__(self):
        self.state = {}


for fn in collectors.COLLECTOR_TOOLS:
    fn("demo-project", Ctx())
```

With `IAM_GUARD_FIXTURE` set they return `{"status": "ok", ...}` and populate
`ctx.state`; the resulting state dict can be fed straight into `analysis.analyze()`,
which gives a full collector→rule-engine integration test with no GCP.

## Adversarial angles that pay off

- **Null-valued keys crash the rule engine.** `analyze()` uses `x.get(k, [])`, which
  returns `None` when the key exists with a JSON `null`. Minimal repro:
  `{"project_iam": {"bindings": null}}` → `TypeError: 'NoneType' object is not iterable`.
  Probe every list/dict field (`members`, `bindings`, `buckets`, `instances`,
  `datasets`, `access_entries`, `metadata`, `service_accounts`) with `null`, and
  non-string scalars (`entity_id: 123`, `email: null`) for `AttributeError`.
- **Collector error handling only catches `GoogleAPIError`/`OSError`.**
  `google.auth.exceptions.DefaultCredentialsError` and `RefreshError` (raised at client
  construction) and fixture `FileNotFoundError`/`json.JSONDecodeError` (read before the
  `try`) escape, so `state["collection_errors"]` stays empty. Simulate a caught error by
  monkeypatching e.g. `collectors.resourcemanager_v3.ProjectsClient` to raise
  `google.api_core.exceptions.PermissionDenied`.
- **False positives**: build a "clean" inventory (UBLA + PAP enforced, `enable-oslogin=TRUE`,
  audit_configs populated, only `roles/viewer`, no external IPs/keys/GPUs) and set
  `IAM_GUARD_TRUSTED_DOMAINS` to the internal domain; it should yield exactly 0 findings.
- **Determinism**: run `json.dumps([f.to_dict() for f in analyze(inv)])` under
  `PYTHONHASHSEED=0/1/2` in separate processes and diff — output must be byte-identical.
- **Settings** are read from the environment on every `get_settings()` call, but in tests
  it is more reliable to construct `iam_guard.config.Settings(trusted_domains=(...),
  untrusted_domains=(...))` and pass it as `analyze(inv, settings)`.
- **Read-only check**: `grep -nE "\.(set_iam_policy|insert|delete|update|create|patch)\(" iam_guard/ -r`
  should return nothing; mutating `gcloud` strings should only ever live inside
  `remediation_commands`.

## Devin Secrets Needed

None for offline testing. Live-mode testing would require GCP Application Default
Credentials plus Vertex AI / Gemini access, which are not available in the sandbox.
