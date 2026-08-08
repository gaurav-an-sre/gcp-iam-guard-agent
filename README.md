# GCP Guard Agents

Two [ADK](https://google.github.io/adk-docs/) **workflow agents** for defending a Google Cloud
project, sharing one deterministic-rule-engine design, one set of read-only collectors and one
deployment path:

| Agent | Question it answers | Entry point |
| --- | --- | --- |
| **IAM Guard** | *Which IAM loopholes could an attacker turn into privilege escalation, cryptojacking or account takeover?* | `iam_guard.agent:root_agent` |
| **Cryptojack Guard** | *Is this project being mined right now, and what stops it happening again?* | `cryptojack_guard.agent:root_agent` |

Both are strictly **read-only and advisory**: every GCP call is a `get`/`list`, and fixes are
emitted as `gcloud` commands for a human to review and run.

---

# IAM Guard

An ADK **workflow agent** that audits Google Cloud IAM for
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
| `IAM_GUARD_MODEL` | Gemini model for all LLM stages (default `gemini-3.6-flash`) |
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
pytest          # 120 tests, no network and no credentials required
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

---

# Cryptojack Guard

IAM Guard finds the *preconditions* for cryptojacking. Cryptojack Guard answers the other half: is
compute in this project being abused for mining **now**, and which guardrails would have prevented
it. It is **advisory only** — it never stops a VM, revokes a key, edits IAM, changes a quota or
applies an org policy. It explains what it saw and prints the commands.

```
SequentialAgent  cryptojack_guard
├── 1. LlmAgent        scope_agent           → state["audit_scope"]
├── 2. ParallelAgent   signal_collectors      (4 read-only collectors, concurrently)
│      ├── LlmAgent    scc_collector         → state["scc_findings"]
│      ├── LlmAgent    monitoring_collector  → state["monitoring_signals"]
│      ├── LlmAgent    capacity_collector    → state["compute_quotas"], state["gce_inventory"]
│      └── LlmAgent    guardrail_collector   → state["billing_budgets"], state["org_policies"]
├── 3. RiskEngineAgent risk_engine           → state["cryptojack_signals"], ["cryptojack_summary"]
└── 4. LlmAgent        report_agent          → state["cryptojack_report"]
```

## Confidence, not alarms

Sustained 100% CPU is not proof of mining — a batch job looks identical. So every signal carries a
confidence level, and the risk engine only escalates when evidence corroborates:

| Confidence | What earns it |
| --- | --- |
| `CONFIRMED` | A mining-specific SCC finding (cryptomining hash match, YARA rule, bad mining domain/IP) |
| `HIGH` | An SCC threat finding on a VM that is *also* saturated, or saturated + internet-facing + running a privileged service account |
| `MEDIUM` | Sustained CPU saturation, capacity in a region the project otherwise never uses, non-mining SCC threat findings |
| `LOW` | GPU utilisation alone, quota near its limit in an expected region, and every preventive gap |

Signals are `detection` (something is happening) or `preventive` (something is missing), and a run
ends in one verdict — `confirmed_mining`, `likely_mining`, `suspected_mining`,
`no_detections_preventive_gaps` or `clean` — plus a 0–100 risk score.

## What it looks at

| Source | Signals |
| --- | --- |
| Security Command Center | Cryptomining hash-match / YARA / bad-domain / bad-IP findings; other active threat findings as corroboration. Misconfiguration findings are ignored — IAM Guard owns those |
| Cloud Monitoring | `compute.googleapis.com/instance/cpu/utilization` above a threshold for a configured duration; optional `agent.googleapis.com/gpu/utilization` |
| Compute Engine quotas | CPU/GPU usage per region — capacity in unexpected regions, usage near the limit |
| Cloud Billing Budgets | No budget covering the project, or a budget with no notification channel, so a spend spike goes unnoticed |
| Organization Policy | `iam.disableServiceAccountKeyCreation`, `compute.vmExternalIpAccess`, `compute.requireOsLogin`, `compute.disableSerialPortAccess`, `compute.disableNestedVirtualization` |
| IAM / GCE inventory | Reuses IAM Guard's `cryptojacking`-category findings as preconditions, and correlates external IPs and privileged attached service accounts with utilisation |

Each detection carries an explanation, investigation steps and advisory commands ordered so evidence
survives — snapshot before stop, then audit-log lookups.

Full rule list: `cryptojack_guard/analysis.py`.

## Run it

Deterministic engine only, no GCP access and no model:

```bash
python scripts/run_local.py --agent cryptojack-guard \
    --rules-only examples/cryptojacked_project.json
```

Full workflow against the recorded project (needs a Gemini model, touches no GCP resources):

```bash
export GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_PROJECT=my-project GOOGLE_CLOUD_LOCATION=us-central1
export CRYPTOJACK_GUARD_FIXTURE=examples/cryptojacked_project.json
export IAM_GUARD_FIXTURE=examples/cryptojacked_project.json
python scripts/run_local.py --agent cryptojack-guard --project demo-prod-1234
```

Live:

```bash
gcloud auth application-default login
gcloud services enable securitycenter.googleapis.com monitoring.googleapis.com \
    compute.googleapis.com billingbudgets.googleapis.com orgpolicy.googleapis.com
export CRYPTOJACK_GUARD_ORG_ID=123456789012           # needed for SCC and org policy
export CRYPTOJACK_GUARD_BILLING_ACCOUNT=01ABCD-234567 # needed for budgets
python scripts/run_local.py --agent cryptojack-guard --project my-prod-project
```

Read-only roles, note the three different scopes:

```bash
# on the audited project
for ROLE in roles/iam.securityReviewer roles/compute.viewer roles/monitoring.viewer; do
  gcloud projects add-iam-policy-binding AUDITED_PROJECT \
    --member="serviceAccount:AGENT_IDENTITY" --role="$ROLE"
done
# on the organisation
for ROLE in roles/securitycenter.findingsViewer roles/orgpolicy.policyViewer; do
  gcloud organizations add-iam-policy-binding ORG_ID \
    --member="serviceAccount:AGENT_IDENTITY" --role="$ROLE"
done
# on the billing account
gcloud billing accounts add-iam-policy-binding BILLING_ACCOUNT \
  --member="serviceAccount:AGENT_IDENTITY" --role="roles/billing.viewer"
```

Any source that cannot be read is recorded in `state["collection_errors"]` and the report states
which signals were unavailable. Unreadable is never reported as clean: a budget read that fails
means "could not check billing", not "no budget exists".

## Configuration

| Environment variable | Purpose |
| --- | --- |
| `CRYPTOJACK_GUARD_PROJECT_ID` | Default project to check |
| `CRYPTOJACK_GUARD_ORG_ID` | Organisation for SCC findings and effective org policies |
| `CRYPTOJACK_GUARD_BILLING_ACCOUNT` | Billing account whose budgets are listed |
| `CRYPTOJACK_GUARD_MODEL` | Gemini model for the LLM stages (default `gemini-3.6-flash`) |
| `CRYPTOJACK_GUARD_CPU_THRESHOLD` / `_CPU_SUSTAINED_MINUTES` | What counts as sustained saturation (default 0.9 for 120 min) |
| `CRYPTOJACK_GUARD_GPU_THRESHOLD` / `_QUOTA_THRESHOLD` | GPU-duty and quota-usage ratios that raise a signal (default 0.8) |
| `CRYPTOJACK_GUARD_LOOKBACK_HOURS` | Monitoring and SCC time window (default 24) |
| `CRYPTOJACK_GUARD_MAX_INSTANCES` / `_MAX_FINDINGS` | Per-run caps |
| `CRYPTOJACK_GUARD_FIXTURE` | Recorded signals JSON; makes all collectors offline |

## Deploy it

Same flow as IAM Guard, selected with `--agent`:

```bash
python deployment/deploy.py create --agent cryptojack-guard \
  --project MY_PROJECT --location us-central1 \
  --staging-bucket gs://MY_PROJECT-agent-staging \
  --audit-project MY_PROJECT \
  --organization ORG_ID --billing-account BILLING_ACCOUNT
```

Then register the printed reasoning engine with Gemini Enterprise exactly as above.

## Limitations

* **Your SCC tier decides whether `CONFIRMED` is reachable at all.** Event Threat Detection
  cryptomining detections and VM Threat Detection's memory-based miner detection require SCC
  **Premium or Enterprise**. On Standard the agent still runs, but mining can only ever be
  *suspected* from utilisation, capacity and guardrail signals.
* A budget is an *alerting* control, not a spend cap — it does not stop a miner, it makes the spike
  visible.
* Quota usage is read per region, so a miner that stays inside existing quota in a region you
  already use yields only a low-confidence signal.
* No egress analysis: identifying mining-pool traffic needs VPC Flow Logs or Cloud NAT logs in
  BigQuery, which this agent does not query.
* **Never verified against a live project.** Collectors, the LLM stages, the Agent Runtime deploy
  and the Gemini Enterprise registration have only been exercised offline against fixtures and unit
  tests. The confidence thresholds will need tuning against real workloads.

---

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
  tools/session_state.py # shared collector session-state and error handling
  normalize.py         # defensive coercion helpers shared by both rule engines
cryptojack_guard/
  agent.py             # root_agent: the SequentialAgent workflow
  analysis.py          # deterministic risk engine (no model, no network)
  models.py            # Signal, Confidence, SignalKind, verdict and scoring
  risk_engine_agent.py # custom BaseAgent wrapping the risk engine as a workflow stage
  tools/collectors.py  # read-only SCC, Monitoring, quota, budget, org-policy collectors
  tools/signals.py     # signal filtering and the human-applied response plan
deployment/            # Agent Runtime deploy (--agent) + Gemini Enterprise registration
examples/              # recorded inventories used by tests and offline runs
scripts/run_local.py   # local runner (live, offline-fixture, or rules-only)
```
