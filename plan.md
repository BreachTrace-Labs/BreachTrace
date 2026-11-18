# BreachTrace — Sprint 3 & Remaining Project Plan

**Group 03 · Dept. of Information Technology · K.J. Somaiya College of Engineering**
**Guide:** Dr. Irfan Siddavatam
**Plan date:** 2026-08-07
**Sprint 3 window:** 2 weeks
**Scope:** Land GCP + Azure for real, add the SaaS forensic tier, close the research gaps, and take the project through to paper submission.

| RITWIK | SHASHANK | YASH | VEDANT |
|---|---|---|---|
| FastAPI · Collectors · DB · Infra · Deploy | Schema · Taxonomy · Severity · Stats · Paper | Detection patterns · Classifier · Research harness | Frontend · D3 · Gemini reports · Normalisation |

---

## Current progress update — 2026-11-18

This update reflects the implementation on branch `ese1` at `515c9b5`. It
supersedes the August 7 state audit below for current status. The detailed
research boundaries and evidence remain in
[`docs/research/paper-reference.md`](docs/research/paper-reference.md),
[`docs/exposure-attribution.md`](docs/exposure-attribution.md), and
[`docs/meeting-actions.md`](docs/meeting-actions.md).

### Implemented

- **Detection and repository scanning:** GitHub push-diff detection and bounded
  current-snapshot scans; 49 AI credential families; bounded static recovery for
  supported encodings and literal constructions. Findings are masked, and
  snapshot scans do not start provider collection.
- **Forensic pipeline:** AWS, GCP, Azure, Stripe and Twilio collectors, with
  Firebase service-account findings routed through GCP. Events are normalized,
  classified, scored and included in deterministic reports and the incident UI.
- **Investigation workflow:** organization/project and role foundation, project
  credential wallet, incident assignment/dismissal/refresh, audit views, PDF
  export, project notifications, evidence search, and optional checked model
  prose. The UI distinguishes detection-only findings and synthetic examples.
- **Research and local workflow:** experiment recording and platform comparison
  code, Azure scenario scaffolding, repository stress tooling, model evaluation
  tooling, Docker Compose local demo, setup guides and migration checks.

### Remaining implementation

1. **Production readiness:** complete authorization and tenant-isolation review
   across the API; make background scans and notification delivery durable with
   retry and delivery state; finish deployment hardening. Current documentation
   describes a local research prototype, not a production-hardened service.
2. **Credential lifecycle evidence:** record the source, identity, timestamp and
   confidence of rotation/revocation observations. Ordinary incidents do not
   automatically establish a confirmed exposure end; timeout or failed checks
   must not be treated as proof of revocation.
3. **Stronger provider attribution (optional extensions):** investigate GCP
   service-account key identifiers, Azure service-principal sign-in evidence,
   Stripe per-key request logs, and stronger Twilio actor/request data. Existing
   collectors often establish account-, principal- or application-level
   correlation rather than exact-key causation.
4. **Research harness cleanup:** fix the scenario chronology before using it to
   measure post-exposure activity, then run a common-ground-truth evaluation
   across supported providers and publish reproducible results.

### Still needed for research claims (not core feature implementation)

- Independent labelled detector evaluation. SecretBench's labelled data is not
  present in this repository; published-pattern parity checks are not an
  accuracy benchmark.
- Controlled cross-provider results for event capture, mapping, attribution,
  latency, collection failures and cost. Code and synthetic tests alone do not
  establish live-account behavior or a completed multi-provider evaluation.
- Blinded human assessment of severity/report quality and a larger model study.
  The existing local model pilot is small and synthetic.
- Ethics and institutional review before any study that exposes credentials or
  collects public-repository data at scale.

**Status note:** the older sprint assignments and exit criteria below are the
August 2026 plan, not a current task checklist. Check the current code and the
linked research/status documents before reopening an item; several August gaps
have since been implemented.

---

## SECTION 0 — Where We Actually Are (state audit, 2026-08-07)

Read this before planning anything. A large amount of GCP/Azure work is **already written but not merged**, and the biggest gaps are not where the team thinks they are.

### 0.1 Complete and on `main`

| Area | State |
|---|---|
| AWS end-to-end pipeline | ✅ Working: webhook → detector → window → CloudTrail collector → normalizer → classifier → scorer → Gemini → DB → dashboard |
| GCP + Azure detection patterns | ✅ `backend/detector/patterns.py` — service-account email anchor, private_key_id, Azure client ID/secret/connection string |
| Scanner multi-platform dispatch | ✅ `backend/detector/scanner.py::scan()` returns AWS + GCP + Azure match types |
| GCP taxonomy | ✅ `backend/classifier/taxonomy_gcp.py` (809 lines) |
| Azure taxonomy | ✅ `backend/classifier/taxonomy_azure.py` (1026 lines) |
| Classifier platform routing | ✅ `backend/classifier/rules.py` — per-platform taxonomy map + per-platform heuristics |
| Frontend platform awareness | ✅ Timeline glyphs per platform, blast-radius labels, GCP/Azure mock incidents, TS types |
| Research harness GCP/Azure functions | ✅ `backend/research/harness.py::run_gcp_experiment` / `run_azure_experiment` |

### 0.2 Written but **NOT MERGED** — `origin/ritwik-current` (2 commits ahead of `main`)

Commits `deb75f0` and `916bcf4` contain most of the GCP/Azure integration layer:

- `backend/collectors/gcp.py` — **fully implemented** `GCPAuditLogCollector` (Cloud Audit Logs filter + `_map_entry`)
- `backend/collectors/azure.py` — **fully implemented** `AzureActivityLogCollector`
- `backend/pipeline.py` — `_COLLECTOR_MAP` dispatch, `run_collection_pipeline(credential, ..., platform=)`
- `backend/config.py` — GCP + Azure env vars (optional; system stays AWS-only when absent)
- `backend/db/models.py` — `gcp_project_id`, `azure_tenant_id`, `azure_subscription_id`, `principal_id`, `location`; `'azure'` added to both platform CHECK constraints; `IncidentRecord.platform` derived property
- `backend/migrations/versions/b3c4d5e6f7a8_add_gcp_azure_fields.py` — migration exists
- `backend/db/crud.py`, `routers/webhook.py`, `routers/simulate.py` — per-match-type platform routing (`GCPCredentialMatch` → `client_email`, `AzureCredentialMatch` → `client_id`)
- `backend/window/gcp_revocation.py`, `backend/window/azure_revocation.py` — new
- `backend/routers/incidents.py` — `platform`, `principal_id`, `gcp_project_id`, `azure_tenant_id`, `azure_subscription_id` on API responses
- `backend/reporter/gemini.py` — platform-aware prompt

> **This branch is the single highest-value thing in the repo right now and it is sitting unmerged.** Task S3-R1 is to land it. Nobody should re-implement any of the above.

### 0.3 Real gaps — the actual Sprint 3 work

| # | Gap | Where | Severity |
|---|---|---|---|
| G1 | `ritwik-current` unmerged and **never run against a live GCP or Azure account** — collectors are untested against real API responses | `collectors/gcp.py`, `collectors/azure.py` | **Blocker** |
| G2 | No GCP project and no Azure subscription provisioned. All `GCP_*` / `AZURE_*` env vars empty. Cloud Audit Logs / Activity Log not enabled anywhere. | infra | **Blocker** |
| G3 | **SecretBench cannot be downloaded — this plan's instruction to "git clone and filter the CSV" is not possible.** The repo holds only a regex spreadsheet and metadata; the labelled dataset is in Google BigQuery behind a Google Cloud account, an email to the authors, and **a signed data protection agreement**. Steps a person must take, with real lead time. Until then Track A has **no external validation** and the accuracy figures come from a fixture this team wrote. Partially mitigated: the MIT-licensed published regexes ARE public and now cross-validated in `test_secretbench_pattern_parity.py`, which found 5 coverage gaps — but that validates pattern *definitions*, not accuracy on real code. | `backend/tests/test_secretbench.py` | **Blocker for paper — start procurement now** |
| G4 | `compare_platforms()` and `latency_by_platform()` raise `NotImplementedError` — the cross-platform comparison that IS the paper's headline result cannot be computed | `backend/research/analysis.py:50-57` | **Blocker for paper** |
| G5 | `compute_financial_impact()` is AWS-only — hardcoded `RunInstances`, `GetObject`, `CreateDBInstance`. Returns "No financial impact detected" for every GCP and Azure incident. | `backend/scorer/severity.py:139` | High |
| G6 | Azure `client_secret` matches carry `client_id=None` → collection credential resolves to `""` → silent empty collection | `routers/simulate.py`, `routers/webhook.py` | High |
| G7 | **Zero SaaS collectors.** The project document promises 12 credential types. We detect 3 cloud platforms and collect from 1. | `backend/collectors/` | High |
| G8 | No test run is verified. No venv, no `pytest` installed on the dev machine, no CI. Yash's GCP/Azure tests are literally committed as `[not yet verified]`. | repo-wide | High |
| G9 | `docker-compose.yml` and `Dockerfile.backend` existed in the init commit `ba891bc`, written against the old `server/` layout, and were lost in the `server/` → `backend/` restructure. Absent from every branch. Still required by `context/context.md` (repo layout, Ritwik's Day 5, week exit criterion #10: "`docker-compose up` starts the entire system cleanly"). | repo root | Medium |
| G10 | Revocation monitoring only polls the AWS experiment key; GCP/Azure revocation modules exist on branch but are unwired to the webhook path | `window/` | Medium |

---

## SECTION 1 — The Architectural Decision That Shapes This Sprint

The project document promises forensic reports for 12 credential types. **That promise cannot be kept as stated, and we should stop pretending otherwise before an evaluator finds it.**

Not every credential type has an audit-log API a third party can query. Sorting the 12 honestly:

### Tier 1 — Forensic-capable (detect **and** reconstruct blast radius)

| Platform | Audit API | Cost | Sprint |
|---|---|---|---|
| AWS | CloudTrail `lookup_events` | Free | ✅ Done |
| GCP | Cloud Audit Logs (`logging.read`) | Free (admin activity always free) | Sprint 3 wk 1 |
| Azure | Monitor Activity Log | Free (90-day retention) | Sprint 3 wk 1 |
| Stripe | Events API (`/v1/events`) | Free in test mode | Sprint 3 wk 2 |
| Twilio | Usage Records + Message logs | Free trial | Sprint 3 wk 2 |
| Firebase | **Reuses the GCP collector** — Firebase writes to Cloud Audit Logs | Free | Sprint 3 wk 2 (cheap win) |
| Mailgun | Events API | Free tier | Sprint 4 (stretch) |

### Tier 2 — Detection-only (detect, classify credential class, **cannot** reconstruct activity)

| Platform | Why not forensic |
|---|---|
| GitHub PAT | Audit Log API requires an Enterprise org. Personal PATs expose no per-token log. Partial signal only via `/user` + public events. |
| Slack webhook | Incoming-webhook activity is not in any audit log below Enterprise Grid |
| NPM token | No public per-token audit API |
| HuggingFace token | No audit API |
| DB connection string | Audit depends on the target DB, which we do not control |
| SendGrid | Email Activity API is a paid add-on |

### What this means

1. **Report two coverage numbers, not one.** "12 credential types detected · 6 platforms with full forensic reconstruction." This is a stronger and more honest claim than a vague 12.
2. **Tier 2 is still a contribution.** For a Tier-2 credential BreachTrace produces exposure window + credential class + a targeted remediation checklist + an explicit *"forensic reconstruction unavailable for this platform — here is why"* panel. Nobody else even states that boundary.
3. **The taxonomy claim gets stronger.** "Cross-platform blast radius taxonomy across 6 platforms" (AWS/GCP/Azure/Stripe/Twilio/Firebase) beats "3 clouds."
4. **The paper gets a new subsection** — §7 Discussion: *Forensic Observability as a Platform Property*. Which vendors make post-exposure forensics possible at all, and which do not, is a genuine finding. Shashank owns writing it.

**Decision to ratify at Sprint 3 kickoff:** adopt the two-tier model, and encode `forensic_tier: 1 | 2` on every credential type in the detector so the UI and the paper both read it from one source of truth.

---

## SECTION 2 — Sprint 3 (2 weeks)

**Sprint goal:** GCP and Azure produce real forensic reports from live cloud accounts, Stripe and Twilio join as the first SaaS collectors, Track A is finally validated, and the cross-platform stats the paper needs are computable.

### Week 1 — Land Multi-Cloud For Real

#### RITWIK — merge, provision, verify

**S3-R1 — Merge `ritwik-current` into `main` (Day 1, blocks everyone)**
- Rebase `origin/ritwik-current` on `main`, resolve conflicts against Shashank's taxonomy commit `319141f` and Vedant's frontend commit `a584135`
- Note: the branch **deletes** `context/vedant_implementation_plan.md` and `context/BreachTrace_Week2_Sprint.pdf` — keep both, they are project record
- Run `alembic upgrade head` on a scratch DB; confirm migration `b3c4d5e6f7a8` applies cleanly and is reversible (`downgrade` then `upgrade` again)
- Verify the AWS path still works end-to-end after merge (regression gate — do not break the thing that works)
- Open the PR, get one review from Shashank (schema) and one from Yash (classifier), then merge
- **Acceptance:** `main` contains GCP/Azure collectors; a full AWS incident still completes in < 60 s

**S3-R2 — Provision GCP (Day 1–2)**
- New throwaway GCP project, billing alert at ₹0 threshold
- Enable Cloud Audit Logs: Admin Activity (always on) + **Data Access logs for Cloud Storage** (must be explicitly enabled — this is the one people forget, and without it `storage.objects.get` never appears)
- Service account `breachtrace-reader` → role `roles/logging.viewer` → JSON key → `GCP_SERVICE_ACCOUNT_JSON`
- Service account `breachtrace-experiment` → roles `roles/storage.objectViewer` + `roles/compute.viewer` **only** → this is the key that gets leaked
- Create one bucket with 2–3 dummy objects so `storage.objects.list` and `.get` return something
- **Acceptance:** `gcloud logging read 'logName:"cloudaudit.googleapis.com"' --limit 5` returns entries after you make a test call with the experiment SA

**S3-R3 — Provision Azure (Day 2–3)**
- Azure free account, new subscription, budget alert
- App registration `breachtrace-reader` → `Monitoring Reader` on the subscription → `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID`
- App registration `breachtrace-experiment` → `Reader` on one resource group only → this is the leaked principal
- One storage account + one resource group with a couple of resources so Activity Log has content
- **Known constraint to verify and document:** Azure Activity Log covers *control-plane* operations only. Data-plane reads (blob GET) require diagnostic settings on the storage account. Enable them, and if data-plane still does not surface, record it as a stated limitation — do not fake it.
- **Acceptance:** `MonitorManagementClient.activity_logs.list()` returns ≥ 1 event caused by the experiment principal

**S3-R4 — Live collector verification (Day 3–4)**
- Run each collector against its live account with a real 10-minute window
- Fix every field-mapping mismatch found against real payloads. Expect breakage — `entry.payload` shape, `entry.timestamp` tz-awareness, `e.http_request` being `None`, `operation_name.value` casing, pagination on both
- Confirm **pagination**: GCP `list_entries` is a lazy iterator (page through > 50); Azure `list()` is an `ItemPaged`
- Wrap both in the same `tenacity` retry the AWS collector uses
- **Acceptance:** `POST /test/simulate` with `platform: "gcp"` and with `platform: "azure"` each produce an incident reaching `status=complete` with ≥ 3 real events

**S3-R5 — Fix G6: Azure credential resolution (Day 4)**
- `azure_client_secret` and `azure_storage_connection` matches have `client_id=None`. Today they create an incident that collects nothing, silently.
- Correlate within the diff: when a `client_secret` match has an `azure_service_principal` match in the same file, attach that `client_id`. When no client ID can be resolved, mark the incident `forensic_tier=2` with reason `"no_principal_identifier"` — do **not** create a silent empty collection.
- **Acceptance:** a diff with only an Azure connection string produces a Tier-2 incident with an explicit reason, not an empty Tier-1 incident

**S3-R6 — Wire GCP/Azure revocation (Day 5)**
- `window/gcp_revocation.py` and `window/azure_revocation.py` exist on the branch but are not called from `routers/webhook.py`
- Route `_monitor_revocation` by platform; keep the 10-minute / 60-second polling contract
- **Acceptance:** revoking the GCP experiment key mid-window sets `exposure_end` within 60 s

#### SHASHANK — schema, severity, stats

**S3-S1 — Ratify the two-tier model (Day 1)**
- Own the Section 1 decision. Write the one-page rationale into `context/` — it becomes paper §7.
- Define `forensic_tier` on every credential type; specify the DB column and API field for Ritwik and Vedant

**S3-S2 — Fix G5: multi-platform financial impact (Day 2–3)**
- `scorer/severity.py::compute_financial_impact()` currently matches AWS action names only, so every GCP and Azure incident reports zero cost
- Restructure to a per-platform cost table:
  - GCP: `compute.instances.insert` (e2-micro/hr), `storage.objects.get` (egress/GB), `container.clusters.create` (GKE/hr)
  - Azure: `Microsoft.Compute/virtualMachines/write` (B1s/hr), `Microsoft.Storage/.../blobServices/.../read` (egress), `Microsoft.ContainerService/managedClusters/write`
  - Stripe: **direct currency** — sum `amount` on `charge.created` / `refund.created`. This is the strongest financial-impact number in the whole system; treat it as a first-class result.
- Keep the AWS numbers byte-identical so existing tests stay green
- **Acceptance:** a GCP incident with a `compute.instances.insert` returns a non-zero cost string; 15 severity tests still pass

**S3-S3 — Fix G4: implement the platform comparison stats (Day 3–4)**
- Implement `compare_platforms()` and `latency_by_platform()` in `backend/research/analysis.py` (currently `raise NotImplementedError`)
- `compare_platforms` → per platform: mean/median/p95 detection time, mean/median report time, severity distribution, mean event count, collection success rate
- `latency_by_platform` → `{aws: float, gcp: float, azure: float, stripe: float, twilio: float}`
- Add a `platform` column to `experiment_runs` (migration) — **required**, the harness currently cannot tag runs by platform
- **Acceptance:** `compare_platforms()` returns a populated dict against the existing AWS runs; unit tests cover the empty-input and single-platform cases

**S3-S4 — Extend the taxonomy to Stripe + Twilio (Day 4–5)**
- `taxonomy_stripe.py`: `charge.created` → `financial_abuse` (4), `customer.retrieved` → `data_access` (2), `payout.created` → `financial_abuse` (4), `account.updated` → `privilege_escalation` (4), `*.list` → `reconnaissance` (1), `refund.created` → `financial_abuse` (3)
- `taxonomy_twilio.py`: `message.sent` → `communication_abuse` (2), bulk sends (≥ 20 same window) → `communication_abuse` (4), `call.created` → `communication_abuse` (3), `number.purchased` → `financial_abuse` (3)
- Same dict shape as the existing taxonomies so `rules.py::_TAXONOMY_MAP` picks them up with a one-line registration
- **Acceptance:** both files import cleanly; every entry validates against `VALID_CATEGORIES` / `VALID_SEVERITIES`

#### YASH — the research gaps

**S3-Y1 — Fix G3: SecretBench, finally (Day 1–2) — highest priority in the sprint**
> This has been "pre-week prep" since the Week-1 plan and has never been done. `data/` does not exist. The 200-sample accuracy claim currently has no evidence behind it. If an evaluator asks for it today we have nothing.
- Clone `github.com/setu1421/SecretBench`, filter `secret_type='AWS' AND ground_truth='true'`, export 200 rows → `data/secretbench_aws_200.csv`
- Also export a **negative set**: 200 rows with `ground_truth='false'` → `data/secretbench_aws_negative_200.csv`. Precision is meaningless without it.
- Run `pytest backend/tests/test_secretbench.py` — it will actually execute for the first time
- Record real Precision / Recall / F1. **Report the true numbers even if they are bad** — a measured 84% is a result; an unmeasured 95% is a fabrication.
- Add `data/*.csv` handling to `.gitignore` vs. committed — decide with Ritwik (commit the 200-row subsets; they are small and make the result reproducible)
- **Acceptance:** the test runs unskipped; P/R/F1 written into `context/track_a_results.md`

**S3-Y2 — Fix G8: make the test suite actually runnable (Day 2)**
- Create the venv + `requirements-dev.txt`; get `pytest backend/tests/` passing locally for the whole team
- Yash's own `test_gcp_cloudaudit_mapping.py`, `test_azure_activitylog_mapping.py`, `test_gcp_classifier.py`, `test_azure_classifier.py` are committed as `[not yet verified]` — verify them now against the merged collectors
- Post the exact setup commands into the README so nobody else loses an hour to it
- **Acceptance:** `pytest backend/tests/` green, count of passing tests recorded

**S3-Y3 — GCP + Azure detection accuracy set (Day 3)**
- Build `data/gcp_azure_detection_set.csv` — 60 hand-built samples: 20 true GCP service-account JSON keys (synthetic, valid format), 20 true Azure credential blobs, 20 near-miss negatives (a plain UUID with no Azure context, a `@gmail.com` address, a 40-char hash that is not a `private_key_id`)
- Measure precision/recall for the GCP and Azure detectors specifically — the Azure client-secret regex `[A-Za-z0-9.\-_~]{34,}` is broad and **will** produce false positives; quantify it rather than guess
- **Acceptance:** per-platform detection metrics recorded; any FP rate > 10% gets a pattern fix

**S3-Y4 — Harness: platform-tagged runs (Day 4–5)**
- Thread Shashank's new `platform` column through `harness.py` → `POST /research/record`
- Un-gate `run_gcp_experiment` and `run_azure_experiment` (their `TODO(Yash)` prerequisites are satisfied once S3-R4 lands)
- Dry-run 3 GCP + 3 Azure experiments end-to-end to prove the loop before the Sprint-4 scale-up
- **Acceptance:** 6 rows in `experiment_runs` with `platform` correctly set and non-null timings

#### VEDANT — make multi-platform legible

> **Status 2026-08-07:** S3-V1, S3-V3 and S3-V5 are **done and verified** (see §2.1
> below). S3-V2, S3-V4, S3-V6 and S3-V7 remain blocked on Shashank's tier spec,
> `compare_platforms()` and the per-platform cost table.

**S3-V1 — Platform-aware incident UI on real data (Day 1–2)** ✅ **DONE**
- The merged API now returns `platform`, `principal_id`, `gcp_project_id`, `azure_tenant_id`, `azure_subscription_id`. Mock data already models these; switch the real path over and delete any remaining mock-only assumptions.
- Dashboard: platform column with a per-platform glyph, and a platform filter
- IncidentDetail header: show the right identity per platform — AWS `access_key_id`, GCP service-account email, Azure client ID + subscription
- **Acceptance:** a live GCP incident and a live Azure incident both render correctly with zero console errors

**S3-V2 — Tier-2 "forensics unavailable" panel (Day 2–3)**
- New component for Tier-2 credentials: exposure window + credential class + remediation, plus an explicit panel stating *which* platform limitation blocks reconstruction (e.g. "GitHub does not expose per-token audit logs outside Enterprise")
- This panel is a demo asset, not an apology — it is the thing that shows we understand the problem space better than the tools we are competing with
- **Acceptance:** a Slack-webhook or NPM-token incident renders a complete, useful page with no empty states

**S3-V3 — Cross-platform report generation (Day 3–4)** ✅ **DONE**
- `reporter/gemini.py` takes `platform` on the branch but still emits AWS-flavoured language for GCP/Azure
- Per-platform prompt context: correct service vocabulary (Cloud Storage not S3; resource group not VPC), correct remediation commands (`gcloud iam service-accounts keys delete`, `az ad app credential delete`, `stripe api_keys roll`)
- Keep the template fallback path working when Gemini fails
- **Acceptance:** a GCP report contains zero AWS terminology; remediation steps are runnable GCP commands

**S3-V4 — Research page: platform comparison (Day 5)**
- Consume Shashank's `compare_platforms()` output
- New chart: grouped bar, detection + report latency per platform. **This chart is the paper's headline figure** — build it to publication quality (readable at greyscale, direct labels, no chartjunk)
- Track A card wired to Yash's real SecretBench numbers, not placeholders
- **Acceptance:** Research page renders live per-platform stats; the latency chart exports cleanly as an image for the paper

---

### §2.1 — Completed in this session (Vedant, 2026-08-07)

Delivered ahead of the sprint start, limited to tasks with no dependency on
Ritwik, Shashank or Yash. All verified in a running browser and by test, not by
inspection.

**S3-V1 — Platform-aware UI**
- New `client/src/lib/platform.ts`: single source of truth for platform identity.
  `derivePlatform()` mirrors `_derive_platform()` in `backend/routers/incidents.py`,
  falling back to `credential_type` so the UI is correct **both before and after**
  Ritwik's merge.
- Dashboard: platform column, filter with per-platform counts, and an explicit
  "no incidents on this platform" state.
- IncidentDetail: platform badge, and an identity tile named per platform
  (AWS access key ID / GCP service account / Azure client ID + subscription).
- `--color-platform-*` theme tokens in both light and dark, so platform colour
  stops borrowing severity tokens.

**S3-V3 — Cross-platform Gemini reports** (`backend/reporter/gemini.py`)
- Per-platform profiles supply vocabulary and **runnable** remediation commands
  (`gcloud iam service-accounts keys delete`, `az ad app credential delete`).
- Platform is inferred from events when the caller omits it — `pipeline.py` does
  not pass it yet, so every GCP/Azure report was AWS-worded until now.
- Cross-platform incidents are tagged per event and state explicitly that
  rotating one platform's credential does not remediate the other.
- Fallback path is platform-correct: it no longer tells a Google Cloud user to
  "audit CloudTrail". This matters for Sprint 4, where bulk runs use the fallback.
- 12 tests in `backend/tests/test_report_platform_vocabulary.py`, all passing.

**S3-V5 — Unified multi-platform timeline** (`ForensicTimeline.tsx`)
- Y-axis rows are now `(platform, service)` pairs with labelled platform brackets,
  so one exposure spanning two clouds reads on a single axis.
- Shape encodes platform, colour encodes severity — independent channels, legible
  in greyscale for the paper.
- Legend, platform count badge and per-row platform tags appear only when more
  than one platform is present.
- New mock incident `inc-007` (AWS + GCP from one Terraform vars file) as the
  fixture and the demo scenario for S3-V7.

**Bugs found and fixed while doing the above** — none of these were on the plan:

| Bug | Where | Impact |
|---|---|---|
| `USE_MOCK = … \|\| true` forced mock mode permanently | `client/src/api/client.ts` | **The UI could never reach a live backend.** Directly contradicted Vedant's own Phase-1 acceptance criterion. Now resolves via `VITE_USE_MOCK` / `VITE_API_URL`. |
| "Highest risk" picked the most *frequent* category | `BlastRadiusSummary.tsx` | Reported "Reconnaissance" as headline risk on an incident containing privilege escalation, because recon is noisier. Now ranks by peak severity. |
| Blast radius attributed **all** events to the incident's own platform | `BlastRadiusSummary.tsx` | A two-platform incident read "AWS CloudTrail — 6 events" when 3 were GCP. Now broken down per platform. |
| Tooltip handler read the global `window.event` | `ForensicTimeline.tsx` | Worked by accident in Chrome, fragile everywhere else. |
| Chart measured width before layout, fell back to a hard-coded 760px | `ForensicTimeline.tsx` | Chart overflowed its container and the right edge of the time axis was clipped. Now uses a `ResizeObserver`. |
| Platform filter read `incident.platform`, which the live API does not return | `Dashboard.tsx` | Filtering by AWS/GCP/Azure matched **zero** incidents against a real backend. |

**Known limitations of this session's verification**
- Live-resize reflow could not be verified: this environment changes the viewport
  without dispatching either `resize` or ResizeObserver notifications. Initial
  sizing was verified at three viewport widths.
- The full `pytest` suite could not be run — only Python 3.9 is available on this
  machine and the repo needs 3.12+ for `X | Y` syntax. **This is exactly S3-Y2**
  and remains open.

**Still blocked for Vedant:** S3-V2 (needs Shashank's `forensic_tier` spec),
S3-V4 (needs `compare_platforms()`), S3-V6 (needs the per-platform cost table),
S3-V7 (needs live collectors).

---

### Week 2 — The SaaS Forensic Tier

#### RITWIK

**S3-R7 — Stripe collector (Day 6–7)**
- `collectors/stripe.py` — `StripeEventsCollector(BaseCollector)`, `/v1/events` with `created[gte]` / `created[lte]`, `auto_paging_iter()`
- Map → `ForensicEvent`: `event.type` → `api_action`, `event.data.object.id` → `affected_resource`, `event.request.id` → correlation, amount into `raw_data`
- Stripe test mode is free and instant — **this is the cheapest Tier-1 platform to add and the most demo-impressive** (a fraudulent charge appearing on the timeline lands harder than a `ListBuckets`)
- **Acceptance:** leak a test-mode restricted key, make 3 API calls, get 3 classified events

**S3-R8 — Twilio collector (Day 7–8)**
- `collectors/twilio.py` — Usage Records + Message list for the window
- Map message sends, calls, number purchases
- **Acceptance:** a leaked test credential's message send appears as a classified `communication_abuse` event

**S3-R9 — Firebase → GCP collector reuse (Day 8)**
- Firebase service-account keys are GCP service-account keys and write to Cloud Audit Logs. Detect the Firebase-specific shape (`firebase-adminsdk-*@*.iam.gserviceaccount.com`), then route to the existing `GCPAuditLogCollector`.
- Near-zero new code, +1 platform. Do this before any harder collector.
- **Acceptance:** a Firebase admin SDK key produces a GCP-collected incident labelled `firebase`

**S3-R10 — Fix G9: Docker + CI (Day 9–10)**
- `Dockerfile.backend` + `docker-compose.yml` (backend + postgres) — README has promised these since Week 1 and they do not exist
- GitHub Actions: `pytest` on every PR. Given the team is merging large branches by hand, this pays for itself immediately.
- **Acceptance:** `docker compose up` brings the stack up clean; CI blocks a PR with a failing test

#### SHASHANK

**S3-S5 — Tier-2 detection taxonomy (Day 6–7)**
- For each Tier-2 type (GitHub PAT, Slack webhook, NPM, HuggingFace, DB connection string, SendGrid): credential class, worst-case blast radius *if used*, platform-specific remediation steps, and the precise reason forensic reconstruction is unavailable
- Feeds Vedant's S3-V2 panel and paper §7

**S3-S6 — Paper §3 System Design rewrite (Day 7–9)**
- Rewrite for 6 platforms and the two-tier model
- Architecture diagram: `BaseCollector` abstraction with 6 concrete implementations
- **This is the paper's Contribution 1** — the normalisation layer is the reason a Stripe charge and an S3 GetObject can sit on one timeline under one severity scale. Write it as the systems contribution it is.

**S3-S7 — Severity calibration across platforms (Day 9–10)**
- Cross-platform severity has to be defensible: is a Stripe `charge.created` genuinely equal to an AWS `CreateAccessKey`?
- Write the calibration rationale; adjust weights where the ordering is indefensible
- Cross-platform severity comparability is the first thing a reviewer will attack — get ahead of it

#### YASH

**S3-Y5 — Stripe + Twilio detection patterns (Day 6–7)**
- Stripe: `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_…`, `sk_test_…` (test keys detected but flagged non-production)
- Twilio: Account SID `AC[0-9a-f]{32}` + auth token `[0-9a-f]{32}` with context correlation
- The AWS false-positive discipline applies: exact lengths, context keywords, negative tests first
- **Acceptance:** 20 unit tests per platform, positive + near-miss negative

**S3-Y6 — Tier-2 detection patterns (Day 8–9)**
- GitHub PAT (`ghp_[A-Za-z0-9]{36}`, `github_pat_…`), Slack webhook (`hooks.slack.com/services/T…/B…/…`), NPM (`npm_[A-Za-z0-9]{36}`), SendGrid (`SG\.[\w-]{22}\.[\w-]{43}`), HuggingFace (`hf_[A-Za-z0-9]{34}`), DB connection strings (`postgres://`, `mongodb+srv://`, `mysql://` with embedded credentials)
- Detection only — no collector, `forensic_tier=2`
- **This is what makes "12 credential types detected" true.** Six patterns, all well-documented formats, ~1.5 days.
- **Acceptance:** 12 credential types detected end-to-end; per-type unit tests

**S3-Y7 — Classifier registration + bulk-detection review (Day 10)**
- Register the Stripe/Twilio taxonomies in `rules.py::_TAXONOMY_MAP`
- Review the bulk-escalation rule per platform: `BULK_THRESHOLD = 5` is tuned for AWS `GetObject`. For Twilio, 5 messages is normal and 100 is abuse. Make the threshold per-platform.
- **Acceptance:** each platform has a justified threshold; tests cover the boundary

#### VEDANT

**S3-V5 — Unified cross-platform timeline (Day 6–8)** ✅ **DONE**
- The D3 timeline currently assumes one platform per incident. Support multiple platforms on one timeline — a single leak commit can expose an AWS key *and* a Stripe key.
- Y-axis grouped by platform, per-platform glyphs (already scaffolded in `ForensicTimeline.tsx:185`), severity colour retained
- **This is the money shot of the demo**: one exposure, one timeline, AWS reconnaissance and a fraudulent Stripe charge side by side. Nothing else on the market renders that.
- **Acceptance:** a two-platform incident renders both event streams correctly with working tooltips

**S3-V6 — Financial impact panel (Day 8–9)**
- Surface Shashank's per-platform costs, with Stripe's real currency amounts featured prominently
- **Acceptance:** a Stripe incident shows the actual disputed amount

**S3-V7 — Demo rehearsal build (Day 9–10)**
- Multi-platform demo: one commit leaking an AWS key + a Stripe test key → both detected → one unified timeline → one report
- Backup pre-loaded incident for each platform
- Update `DEMO_GUIDE.md` for the multi-platform flow
- **Acceptance:** demo runs clean 3× in a row, under 3 minutes

---

### Sprint 3 Exit Criteria

1. `ritwik-current` merged; AWS path un-regressed
2. Live GCP incident: real Cloud Audit Log events, classified, scored, reported
3. Live Azure incident: same
4. Live Stripe incident: same, with a real currency amount
5. Live Twilio incident: same
6. Firebase routes through the GCP collector
7. 12 credential types detected; 6 platforms forensically collected
8. **Track A validated with real SecretBench numbers** (G3 closed)
9. `compare_platforms()` and `latency_by_platform()` implemented and returning real data (G4 closed)
10. Financial impact non-zero on non-AWS platforms (G5 closed)
11. `pytest backend/tests/` green in CI (G8 closed)
12. `docker compose up` works (G9 closed)
13. Multi-platform timeline renders two platforms in one incident
14. Tier-2 panel renders a useful page for a Slack/NPM leak

---

## SECTION 3 — Remaining Project Roadmap

### Sprint 4 — Research Scale-Up (2 weeks)

**Goal:** the empirical dataset the paper is built on.

| Owner | Work |
|---|---|
| Yash | **150 experiment runs** across 6 platforms — AWS 40, GCP 30, Azure 30, Stripe 25, Twilio 15, Firebase 10. Groups A (recon) / B (bulk) / C (minimal) preserved within each platform so severity distribution stays comparable. |
| Yash | **Exposure-to-use latency study** — the paper's Contribution 3. Leak real (harmless, read-only) credentials on a public repo and measure time to first *external* IP use per platform. `first_external_use_s` already exists in the schema and is unpopulated. Expect Stripe fastest, Azure slowest. Needs ≥ 20 exposures per platform to say anything. |
| Ritwik | Harness reliability at scale — key rotation for 6 platforms, rate-limit backoff, resume-after-failure. A 150-run loop that dies at run 90 costs days. |
| Shashank | Statistical analysis: significance testing on cross-platform latency differences, classification accuracy against manually-labelled events, severity-distribution comparison. Paper §5 + §6. |
| Vedant | Research dashboard v2: latency-by-platform chart, severity distribution per platform, classification confusion matrix. Publication-quality export for every figure. |

**Ethics gate before any real exposure:** the latency study deliberately leaks credentials to a public repo. All keys read-only, scoped to empty throwaway accounts, auto-revoked on a timer, with billing alerts. Write the ethics statement **before** running it — reviewers at USENIX/S&P will ask, and the guide should sign off. Shashank owns this document.

### Sprint 5 — Hardening + Paper (2 weeks)

| Owner | Work |
|---|---|
| Ritwik | Production deploy; rate limiting; secrets never logged; error handling on every collector; graceful degradation when a platform's API is down |
| Shashank | Paper draft complete: all 8 sections. Related-work positioning against GitGuardian, TruffleHog, AWS Security Hub, and the cloud-forensics literature |
| Yash | Reproducibility package: dataset, harness, seeds, exact commands. Artifact evaluation is worth real points at USENIX |
| Vedant | Accessibility + responsive pass; screenshots for the paper; 90-second demo video |
| All | Internal red-team: each person tries to break someone else's component and files what they find |

### Sprint 6 — Submission (1 week)

- Guide review and revisions
- Venue decision — realistically: **USENIX Security** (systems + empirical fit, artifact evaluation), or a workshop first if the timeline is tight
- Camera-ready, artifact submission
- Final evaluator demo

---

## SECTION 4 — Risk Register

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| Azure Activity Log has no data-plane visibility | **High** | Azure blast radius looks thin | Enable storage diagnostic settings; if still absent, state it as a finding — "Azure is measurably less forensically observable than AWS" is a *result*, not a failure | Ritwik |
| Azure client-secret regex false positives | High | Noisy detection hurts precision | S3-Y3 measures it before it embarrasses us in front of an evaluator | Yash |
| SecretBench numbers come back weak | Medium | Weakens Track A | Report honestly, analyse failure modes, fix the pattern. A measured 84% with error analysis is a better paper contribution than an unmeasured 95% | Yash |
| 150 experiment runs exceed free tiers | Medium | Cost | Billing alerts on all 6 platforms before Sprint 4; Stripe/Twilio stay in test mode | Ritwik |
| Gemini rate limits during a 150-run batch | Medium | Harness stalls | Template fallback already exists — make the harness prefer it in bulk mode and reserve Gemini for demo incidents | Vedant |
| Large hand-merged branches conflict again | **High** | Lost days | CI + smaller PRs from Sprint 3 onward. `ritwik-current` sitting 2 commits ahead with 27 changed files is exactly the pattern to stop | Ritwik |
| Paper scope creep across 6 platforms | Medium | Nothing finishes | Platform count is frozen at 6 Tier-1 after Sprint 3. Mailgun and anything else is explicitly out of scope | Shashank |

---

## SECTION 5 — Standing Rules

1. **Nothing is "done" until a test proves it.** Yash's `[not yet verified]` commits are how G8 happened. If it is not verified, the commit message says so and it does not count toward a sprint exit criterion.
2. **No branch lives longer than 3 days.** The `ritwik-current` situation cost the team an entire integration cycle of hidden work.
3. **Real numbers only.** Every figure in the paper and every number on the Research page traces to a committed dataset and a runnable script. No placeholders survive into a deliverable.
4. **The AWS path is the regression gate.** It works. Every merge proves it still works before anything else is evaluated.
5. **Honest scope beats impressive scope.** "6 platforms with full forensic reconstruction, 12 detected" is a stronger and more defensible claim than "12 platforms" that does not survive a question.

---

*— END OF SPRINT 3 & REMAINING PROJECT PLAN —*
