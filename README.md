# IAM Guard

An [ADK](https://google.github.io/adk-docs/) **workflow agent** that audits Google Cloud IAM for
loopholes an attacker can turn into privilege escalation, **cryptojacking**, or **phishing /
account takeover**, then hands back a prioritised remediation plan. It is designed to be deployed
on **Agent Runtime** (Agent Engine) and registered as a custom agent in **Gemini Enterprise**, so a
GCP platform owner can just ask: *"audit IAM in project my-prod-project"*.

The agent is strictly **read-only**: every GCP call is a `get`/`list`. It never edits IAM; it emits
the `gcloud` commands for a human to review and run.

## Workflow shape

```
SequentialAgent  iam_guard
├── 1. LlmAgent        scope_agent           → state["audit_scope"]
├── 2. ParallelAgent   inventory_collectors   (4 read-only collectors, concurrently)
│      ├── LlmAgent    iam_collector         → state["project_iam"], state["service_accounts"]
│      ├── LlmAgent    gce_collector         → state["gce_inventory"]
│      ├── LlmAgent    gcs_collector         → state["gcs_inventory"]
│      └── LlmAgent    bigquery_collector    → state["bigquery_inventory"]
├── 3. RuleEngineAgent rule_engine           → state["findings"], state["findings_summary"]
└── 4. LlmAgent        report_agent          → state["security_report"]
```

Two design choices are worth calling out:

* **Stage 3 contains no model call.** `iam_guard/analysis.py` is a plain Python rule engine, so the
  same inventory always yields exactly the same findings — you can unit test and diff them. The LLM
  only explains and prioritises what the rules found; it cannot invent or silently drop a finding.
* **Raw IAM policies never enter the model context.** Collector tools write full inventories into
  session state via `ToolContext.state` and return only a small summary to the model. That keeps
  large policies out of the prompt and keeps token cost flat as the project grows.

## What it detects

| Area | Examples of rules |
| --- | --- |
| Project IAM | `allUsers`/`allAuthenticatedUsers` bindings, legacy basic roles, unconditional IAM-admin roles, project-wide impersonation grants, consumer/external accounts, quota & billing control |
| Attack paths (correlated) | `iam.serviceAccountUser` + any "run code" role (`compute.instanceAdmin.v1`, `run.admin`, `cloudbuild.builds.editor`, …) → attach a privileged SA to a workload and steal its metadata token; impersonation + bulk data read |
| Service accounts | user-managed (exported) keys, public or external impersonation bindings, disabled SAs that still hold roles |
| Compute Engine | default SA with `cloud-platform` scope, privileged SA attached, internet-facing VMs, OS Login not enforced, project-wide SSH keys, interactive serial console, unexplained GPU capacity |
| Cloud Storage | public buckets, external write access, uniform bucket-level access off, public access prevention not enforced, legacy ACL roles |
| BigQuery | datasets shared with `allAuthenticatedUsers`, domain-wide sharing, `projectEditors` as dataset OWNER, external accounts with WRITER |

Every finding carries a severity, the threat categories it enables (`cryptojacking`,
`phishing_takeover`, `privilege_escalation`, `data_exfiltration`, `public_exposure`,
`weak_hygiene`), the evidence, and — where a safe one exists — the exact `gcloud` fix. The rule
engine also produces a 0–100 risk score.

Full rule list: `iam_guard/analysis.py`. Role knowledge base: `iam_guard/roles.py`.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,deploy]"
```

### Try it with no GCP access at all

The rule engine runs standalone against a recorded, deliberately-vulnerable inventory:

```bash
python scripts/run_local.py --rules-only examples/vulnerable_inventory.json
```

### Run the full agent against the recorded inventory

Needs a Gemini model (Vertex AI or an API key), but touches no GCP resources:

```bash
export GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_PROJECT=my-project GOOGLE_CLOUD_LOCATION=us-central1
export IAM_GUARD_FIXTURE=examples/vulnerable_inventory.json
export IAM_GUARD_TRUSTED_DOMAINS=example.com
python scripts/run_local.py --project demo-prod-1234
```

### Run a live audit

```bash
gcloud auth application-default login
export IAM_GUARD_TRUSTED_DOMAINS=yourcompany.com
python scripts/run_local.py --project my-prod-project

# or use the ADK dev UI
adk web
```

The caller (or the deployed agent's identity) needs these **read-only** roles on the audited
project:

```bash
for ROLE in roles/iam.securityReviewer roles/compute.viewer \
            roles/storage.objectViewer roles/bigquery.metadataViewer; do
  gcloud projects add-iam-policy-binding AUDITED_PROJECT \
    --member="serviceAccount:AGENT_IDENTITY" --role="$ROLE"
done
```

Collectors degrade gracefully: if one service can't be read, that service's error is recorded in
`state["collection_errors"]`, the rest of the audit continues, and the report states which services
were not checked.

## Configuration

| Environment variable | Purpose |
| --- | --- |
| `IAM_GUARD_PROJECT_ID` | Default project to audit when the user doesn't name one |
| `IAM_GUARD_MODEL` | Gemini model for all LLM stages (default `gemini-2.5-flash`) |
| `IAM_GUARD_TRUSTED_DOMAINS` | Comma-separated internal domains. **Set this** — it is what makes external-principal detection meaningful |
| `IAM_GUARD_UNTRUSTED_DOMAINS` | Consumer domains always treated as risky (defaults to gmail.com, outlook.com, …) |
| `IAM_GUARD_MAX_BUCKETS` / `_MAX_DATASETS` / `_MAX_INSTANCES` | Per-run inspection caps |
| `IAM_GUARD_FIXTURE` | Path to a recorded inventory JSON; makes all collectors offline |

## Deploy to Agent Runtime and Gemini Enterprise

1. Enable the APIs and create a staging bucket:

   ```bash
   gcloud services enable aiplatform.googleapis.com storage.googleapis.com \
       discoveryengine.googleapis.com
   gcloud storage buckets create gs://MY_PROJECT-agent-staging --location=us-central1
   ```

2. Deploy to Agent Runtime:

   ```bash
   python deployment/deploy.py create \
     --project MY_PROJECT --location us-central1 \
     --staging-bucket gs://MY_PROJECT-agent-staging \
     --audit-project MY_PROJECT \
     --trusted-domains yourcompany.com
   ```

   This prints the resource name
   `projects/MY_PROJECT/locations/us-central1/reasoningEngines/RESOURCE_ID`, and the commands to
   grant the agent's identity the read-only audit roles. Grant those before the first run.

3. Register it with your Gemini Enterprise app so it appears in the web app:

   ```bash
   python deployment/register_gemini_enterprise.py \
     --project MY_PROJECT --app-id MY_GEMINI_ENTERPRISE_APP_ID \
     --reasoning-engine projects/MY_PROJECT/locations/us-central1/reasoningEngines/RESOURCE_ID
   ```

   Then share the agent with users from the Gemini Enterprise console (**Agents → agent → Share**).
   `--list` shows what's already registered and `--delete AGENT_ID` unregisters.

`deployment/deploy.py` also supports `update`, `list` and `delete`.

## Tests and lint

```bash
pytest          # 24 tests, no network and no credentials required
ruff check .
ruff format --check .
```

## Limitations

* Reviews **IAM allow policies only**. It does not evaluate deny policies, organisation policies,
  VPC Service Controls, firewall rules, or IAM Recommender usage data.
* Single project per run, and inherited folder/organisation bindings are not expanded.
* Group membership is not resolved, so a group's effective blast radius is not measured.
* `SequentialAgent`/`ParallelAgent` are marked deprecated in ADK 2.x in favour of the new
  graph-based `Workflow` API, which Agent Engine's `AdkApp` does not yet accept. The workflow is
  deliberately built from the template agents so it deploys today; migration is a
  self-contained change to `iam_guard/agent.py`.

## Layout

```
iam_guard/
  agent.py             # root_agent: the SequentialAgent workflow
  analysis.py          # deterministic rule engine (no model, no network)
  roles.py             # role knowledge base: escalation / execution / data-read roles
  models.py            # Finding, Severity, ThreatCategory, scoring
  rule_engine_agent.py # custom BaseAgent wrapping the rule engine as a workflow stage
  prompts.py           # instructions for the LLM stages
  tools/collectors.py  # read-only GCP collectors (IAM, SAs, GCE, GCS, BigQuery)
  tools/findings.py    # findings/remediation lookup tools for the reporting stage
deployment/            # Agent Runtime deploy + Gemini Enterprise registration
examples/              # recorded vulnerable inventory used by tests and offline runs
scripts/run_local.py   # local runner (live, offline-fixture, or rules-only)
```
