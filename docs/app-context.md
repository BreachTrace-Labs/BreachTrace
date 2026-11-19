# BreachTrace application context

This document describes the application as implemented in this repository on 17 November 2026. It is intended as a working map of the product, its code paths, and the experience a person actually has when using it. It describes current behavior, including important gaps, rather than a proposed product design.

## What the app does

BreachTrace looks for credential candidates in GitHub source code and helps an operator investigate a detected leak. It supports two different entry points:

1. **Scan an existing repository snapshot.** The operator pastes a GitHub repository URL. BreachTrace downloads the default branch at a pinned revision and scans its current text files. Results appear in the Connect page's scan result. This is a point-in-time inventory; it does not establish when a key first appeared and does not create an incident or start cloud forensics.
2. **Monitor new pushes through a GitHub webhook.** A valid, signed push payload starts analysis of added lines in the pushed commits. A qualifying match creates an incident with the commit timestamp as its estimated exposure start. A supported, sufficiently identified credential can then trigger provider log collection and a forensic report.

The application also offers incident search, report generation, optional model-written report prose, research exports, simulation endpoints, and synthetic demo data. Detection is a lead for investigation. A pattern match does not prove a credential is valid, that a repository was public, or that a provider event was caused by the leaked credential.

## The central visibility rule

**In the real webhook workflow, a Monitor incident appears only after BreachTrace observes a qualifying credential in content added by a signed GitHub push.** The push commit timestamp becomes the estimated exposure start. A key merely present in the backend's local environment file, a provider account, or an older repository snapshot is not by itself a Monitor incident. A newly committed `.env` file can create an incident if its added lines match the detector.

There are deliberate exceptions for test data: the simulation endpoint can create test incidents from supplied diffs, and the AI demo seeder creates clearly labeled synthetic incidents. These are not evidence of real GitHub exposure.

An incident's processing status and a key's exposure status are different things. **Complete** means the analysis pipeline finished; it does not mean the key was rotated, the exposure ended, or every provider action was captured. An empty forensic timeline can mean no eligible events occurred in the collection window, or that the provider could not supply them. The collection status and error message are therefore part of the interpretation.

| Input or event | Where the user sees it | Incident created? | Provider forensics started? |
| --- | --- | --- | --- |
| Current default-branch snapshot scan finds a candidate | Connect scan result | No | No |
| Signed push adds a supported, collectable credential | Monitor, then incident detail | Yes | Yes, if required account and access information is available |
| Signed push adds a detection-only candidate | Monitor, then incident detail | Yes | No |
| Key is present only in an old file with no new qualifying push | Nowhere automatically; a snapshot scan can find it | No | No |
| Operator submits a test diff or seeds demo data | Monitor, labeled by the test or demo path | Yes, synthetic/test | Depending on test input and tier |

## Architecture at a glance

~~~mermaid
flowchart LR
    User[Operator in React UI] --> API[FastAPI backend]
    GitHub[GitHub push webhook] --> API
    API --> Snapshot[Snapshot scan jobs]
    API --> Detector[Credential detection and match resolution]
    Snapshot --> SnapshotResults[Connect scan results]
    Detector --> Incidents[(Incidents and collection status)]
    Incidents --> Pipeline[Forensic pipeline]
    Pipeline --> Providers[AWS / GCP / Azure / Stripe / Twilio]
    Providers --> Events[(Normalized forensic events)]
    Events --> Reports[Severity, financial assessment, report]
    Reports --> Search[Incident search index]
    Incidents --> Monitor[Monitor and incident detail]
    Reports --> Monitor
    Search --> User
~~~

The frontend is a React/Vite app. The backend is FastAPI with SQLAlchemy persistence, provider collectors, a report pipeline, and a retrieval index. PostgreSQL is the documented local database. GitHub supplies repository archives for snapshot scans and commit diffs for webhook scans. Provider collectors query external audit or event APIs only for supported forensic tiers.

The primary backend entry point is [backend/main.py](../backend/main.py). The page routes are in [client/src/App.tsx](../client/src/App.tsx). The relevant persistence model is [backend/db/models.py](../backend/db/models.py).

## Actual user journey

### 1. Prepare and open the local app

The documented local setup creates a Python virtual environment, installs frontend packages, starts an isolated PostgreSQL service, prepares the local environment, and starts backend and frontend processes through [scripts/local_dev.py](../scripts/local_dev.py). The documented frontend address is `http://127.0.0.1:5173`; the API documentation is at `http://127.0.0.1:8000/docs`. Configuration examples are in [.env.example](../.env.example), and setup instructions are in [README.md](../README.md) and [local-testing.md](local-testing.md).

The UI can use mock preview data when configured for that mode. For a live local test, the frontend must address the running backend and the backend must reach its database. The backend's `/health` route returns a simple service status; it does not by itself verify GitHub or provider access.

The app is currently intended for a local operator and research workflow. It does not implement hardened multi-tenant authentication. Some operational settings and scan endpoints enforce loopback access; this should not be read as a complete production security boundary.

Each installation is explicitly limited to one organisation, enforced by the database. Administrators and security leads have organisation-wide search, research and repository snapshot access, including legacy unassigned records; the selected project does not filter these features. Developers can access their assigned projects but cannot use these organisation-wide endpoints. Existing databases containing more than one organisation must be resolved before applying the migration; no data is removed automatically.

### 2. Scan the codebase that already exists

Repository URL scans review the current snapshot. An administrator or security lead can explicitly add a finding to Monitor for the matching project. The record is detection only: its timestamp is when the snapshot was observed, the exposure start is unknown, and no provider collection starts. Masked hints can match different keys, so possible existing incidents must be reviewed. Historical Git scanning and inferred first exposure remain separate capabilities. Users who want monitoring for subsequent pushes can register the project webhook.

On **Connect**, the user pastes a root GitHub URL such as `https://github.com/owner/repo` and chooses **Scan repository**. The backend validates the URL, resolves the default branch to a commit SHA, downloads a bounded archive, and scans regular UTF-8 text files without executing repository code. A private repository needs backend GitHub access through `GITHUB_TOKEN`.

The scan is queued in the database. The UI polls for queued, scanning, complete, or failed status and restores the most recent scan ID on the same browser. On completion it shows the pinned branch and revision, candidate type, masked hint, file and line, detection method, confidence, and any partial-scan/exclusion information. A failed job shows an error; a large repository can hit documented download, file, text, finding, or time limits.

The result is explicitly **snapshot only**: it has no exposure start, no incident ID, and no provider collection. The user can use it to find code that currently contains a suspicious string, but it cannot answer when that string entered Git history. New job metadata and masked results are stored in the database, and interrupted jobs are eligible for recovery when their lease expires. Earlier scans written only to `data/repository-scans/` are not automatically imported.

Snapshot logic is in [backend/repository_snapshot.py](../backend/repository_snapshot.py), [backend/detector/repository.py](../backend/detector/repository.py), and [backend/routers/repositories.py](../backend/routers/repositories.py). The UI is [client/src/components/RepositoryScan.tsx](../client/src/components/RepositoryScan.tsx).

### 3. Optionally monitor future commits

The Connect page can register a GitHub push webhook using `GITHUB_TOKEN`, or the user can create one manually in GitHub repository settings. Registration needs token permission to administer that repository's webhooks. The GitHub Payload URL must be publicly reachable; `localhost` is not reachable from GitHub. For local development, an HTTPS tunnel can forward to the backend's `/webhook/github` route. The configured webhook secret must match `GITHUB_WEBHOOK_SECRET` on the backend, and GitHub should send JSON with SSL verification enabled.

The Connect form can also request a snapshot scan after registration; it scans the selected project's repository even if the standalone scan URL was edited. That scan and the future-push monitor are independent flows. Registering a webhook does not backfill old commits. The webhook registration and delivery routes are in [backend/routers/webhook.py](../backend/routers/webhook.py); the form is [client/src/pages/Connect.tsx](../client/src/pages/Connect.tsx).

### 4. A new push becomes an incident

On `POST /webhook/github`, the backend first checks the `X-Hub-Signature-256` HMAC against the configured webhook secret. An invalid signature is rejected. The route processes push events, reads each commit in the payload, fetches the commit diff through GitHub, and scans **added lines**. Nearby unchanged lines can supply context, but deleted lines and unrelated hunks do not become new leak candidates.

The detector normalizes a match, assigns a forensic tier, records a masked hint and a credential fingerprint, and creates an incident row for each resolved candidate. It uses the commit timestamp as `exposure_start`. This is an estimate tied to the observed commit, not proof of first-ever exposure in the repository or public visibility. If the match is collectable, the webhook schedules the forensic pipeline; otherwise it finalizes a detection-only report and indexes the incident.

The diff scanner is [backend/detector/scanner.py](../backend/detector/scanner.py), pattern families are in [backend/detector/patterns.py](../backend/detector/patterns.py) and [backend/detector/ai_keys.py](../backend/detector/ai_keys.py), and collector routing is in [backend/detector/match_resolver.py](../backend/detector/match_resolver.py).

### 5. Investigate in Monitor

The **Monitor** dashboard loads `/incidents` and refreshes it every three seconds. It shows incident counts, severity, active status, credential families, and a list that can be filtered by provider/type. Snapshot candidates do not appear here. Selecting an incident opens its detail page, which also polls while analysis runs.

The detail page shows the detected credential family and masked hint, repository and commit, exposure time, processing state, severity, report, forensic timeline, source IPs and resources when known, financial/compliance assessments, remediation checklist, and PDF export. A detection-only incident explains why no live forensics ran. A collector failure is shown through collection status and its sanitized error, not as proof of no activity. The UI is [client/src/pages/Dashboard.tsx](../client/src/pages/Dashboard.tsx) and [client/src/pages/IncidentDetail.tsx](../client/src/pages/IncidentDetail.tsx); responses are assembled in [backend/routers/incidents.py](../backend/routers/incidents.py).

For supported incidents, **Refresh logs** can rerun the collector. Project incidents use their project's verified wallet reader; unassigned legacy incidents use backend environment configuration. Missing, pending, failed or unreadable project wallet entries stop collection without falling back to global credentials. Stripe requires a reader in the same account and test/live mode; the UI asks the operator to confirm the account relationship. A Twilio detection-only API key can be associated with an owning Account SID beginning `AC` when the reader matches that account. Refresh cannot manufacture missing provider history or prove which credential performed an account-wide action.

An Azure client secret detected without an application ID is initially detection-only. An administrator or security lead can explicitly associate the owning application (client) ID on the incident and start collection using the project's Azure wallet reader. This records the operator's association, not independent proof of ownership. Azure Activity Log events are matched to the application identity, and do not identify which particular client secret was used.

### 6. Search, configure reports, and export research data

**Search** retrieves indexed incident evidence through `/assistant/search`. It can scope by incident, time range, platform, category, severity, and other parsed terms. Exact event-time questions can query stored event rows. The normal behavior is retrieval with citations and suggested follow-ups; a grounded answer from a model is optional and requires a configured provider. Search covers data that was stored and indexed; it is not a live search of GitHub or all provider logs. See [backend/routers/assistant.py](../backend/routers/assistant.py) and [backend/rag/search.py](../backend/rag/search.py).

**Settings** selects deterministic reporting by default or an optional OpenAI, Anthropic, Gemini, Ollama, or local GGUF writer. Deterministic facts, severity, financial estimates, and checklist logic are generated first; model prose can upgrade the report after completion and is validated before use. A model is not required for incident detection or deterministic reports. Entered API keys are held in backend process memory; environment configuration can supply provider credentials. See [backend/routers/settings.py](../backend/routers/settings.py), [backend/model_settings.py](../backend/model_settings.py), and [backend/reporter/writers.py](../backend/reporter/writers.py).

**Research** exposes experiment records, platform information, and exports. Ordinary snapshot scans and webhook incidents do not automatically become research experiment runs. Test simulations and the synthetic AI demo are separate from live evidence. See [backend/routers/research.py](../backend/routers/research.py), [backend/routers/simulate.py](../backend/routers/simulate.py), and [backend/research/ai_demo.py](../backend/research/ai_demo.py).

## Detection and qualification logic

The detector recognizes cloud, SaaS, database, and AI provider credential shapes. The AI catalog contains 49 credential families. Some families use distinctive prefixes; others require a provider name or nearby key assignment. Bounded static recovery can recognize common literal encodings and simple source-level constructions, but it does not execute code, solve arbitrary data flow, decrypt unknown formats, or validate every candidate with a provider. [ai-detection.md](ai-detection.md) details the AI catalog and recovery rules.

Matches are routed to one of two broad outcomes:

- **Tier 1 / collectable:** enough information exists to attempt a supported provider collector, subject to authorization, scope, retention, and API availability.
- **Tier 2 / detection only:** the string is worth showing as a leak candidate, but BreachTrace lacks a supported, safe, or adequately identified collection path. The incident still receives a report and can appear in search.

Qualification depends on family-specific context. For example, Stripe `sk_` and `rk_` keys can enter its collector path; a Twilio `SK` API key SID needs an unambiguous owning `AC` Account SID before account-scoped collection. AI provider key families are currently detection-only. The displayed credential value is a masked hint, not a recovered full secret. A candidate's label or severity must not be interpreted as provider-side validation.

The repository scanner has bounded work: currently 10 MiB per file, 1 GiB total scanned text, 200,000 files, 10,000 findings, ten minutes for scanning, 2 GiB compressed archive, and five minutes for archive download. It excludes dependency/build directories such as `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, and `.next`; it skips binaries, symlinks, special files, submodules, and Git history. Hidden `.env` files can be scanned when present in the archive. Limits and exclusions are part of the result's completeness assessment.

## Forensic collection and timeline semantics

The pipeline moves a collectable incident through collection, normalization/persistence, classification, severity and impact scoring, report creation, and search indexing. It saves provider events as normalized forensic rows and records a collection status. The report starts with deterministic prose; a configured model may later improve the prose without changing the underlying events. Collector failure moves the incident to an error state with a visible reason. The implementation is [backend/pipeline.py](../backend/pipeline.py), the schema is [backend/db/models.py](../backend/db/models.py), and report facts/composition live in [backend/reporter/](../backend/reporter/).

**The collection window covers up to 30 days before collection.** Provider access, logging, retention and collection limits determine what is available. Earlier events appear as context and do not create an incident before the exposure trigger. Severity, impact and reports use events at or after detected exposure. A refresh reruns collection without changing the original exposure timestamp.

The exposure start is an estimate from the commit timestamp; repository visibility and first exposure are not independently confirmed. Ordinary incidents do not automatically track revocation. A recorded closure timestamp does not currently carry independent provider verification. See [exposure and attribution scope](exposure-attribution.md) for the decisions, possible provider-specific improvements, and current limits.

| Provider or family | Collection source and current meaning | Important boundary |
| --- | --- | --- |
| AWS | CloudTrail activity within the requested window | Requires usable credentials and logging access; returned activity needs contextual interpretation. |
| GCP / Firebase | Cloud Audit Logs within the requested window | Subject to project identity, permissions, and log availability. |
| Azure | Azure Activity Log, primarily control-plane activity; filters locally by exact application ID in identity claims or caller | Requires the necessary tenant/subscription/principal context; it cannot identify which client secret was used and is not a complete data-plane history. |
| Stripe | Stripe Events API account-wide state-change events, queried over its available 30-day window | No read-only requests or per-key attribution. A successful read is not evidence that the leaked key made an event. |
| Twilio | Account-scoped outbound Messages, Calls, and Monitor Events | Needs an owning `AC` Account SID and authorized reader; records are account activity, not per-key attribution. Message bodies are not retained by the collector. |
| Other SaaS, database, and AI families | Detection and report only | No live provider event collection in the current implementation. |

Stripe deserves a specific example because an empty timeline is easy to misread. The integrated backend collector queries the Events API across its available 30-day window, so it can include events from before the key was committed. Those events describe account activity; they do not establish that the exposed key caused them. The standard Events API represents state changes rather than every API request, and read-only requests are absent. The optional CLI request stream is separate and is not required for this collection path.

For new sandbox API requests, including GET requests, a restart-managed Stripe CLI sidecar streams metadata into the incident timeline. It records only while connected, cannot retrieve prior requests, and does not identify which key caused a request. Only request ID, method, reduced path, status, and timestamp are retained; payloads and query strings are excluded. See [stripe-request-stream.md](stripe-request-stream.md) for local Docker setup and deployment on an always-on host.

Twilio's account SID, API key SID, and key secret serve different roles: an `SK` SID is an API key identifier, an `AC` SID identifies the owning account, and an authorized reader is needed to query account logs. A detected `SK` alone is not enough to attribute or retrieve account-wide events. Collector details are in [backend/collectors/stripe.py](../backend/collectors/stripe.py) and [backend/collectors/twilio.py](../backend/collectors/twilio.py).

## Stored data, endpoints, and runtime behavior

An incident stores its credential family, masked hint, repository, commit hash, exposure start/end when known, forensic tier, processing status, severity, report/remediation content, and provider identification needed for collection. Related rows hold normalized events and collection status. The latest collection outcome and error are returned with incident detail. A full leaked secret is not stored as a reusable Stripe incident credential; it is passed transiently to initial collection. Avoid putting real credentials in demo payloads, documentation, or commit history.

| Route | Role |
| --- | --- |
| `GET /health` | Basic backend liveness. |
| `POST /repositories/scan`, `GET /repositories/scans/{id}` | Start and inspect a current-codebase snapshot scan. |
| `POST /webhook/github` | Receive signed GitHub push deliveries. |
| `POST /webhook/register`, `GET /webhook/info` | Register a push hook and obtain the suggested callback URL. |
| `GET /incidents`, `GET /incidents/{id}` | Monitor list and detailed incident/evidence view. |
| `GET /incidents/{id}/timeline`, `GET /incidents/{id}/report.pdf` | Timeline and report export. |
| `POST /incidents/{id}/refresh`, `POST /incidents/{id}/twilio-account` | Rerun provider collection or associate a Twilio account. |
| `POST /assistant/search`, `GET /assistant/status` | Search stored/indexed evidence and inspect search readiness. |
| `GET /settings/model`, `PUT /settings/model`, `POST /settings/model/test` | Configure and test report generation. |
| `GET /research/export`, `GET /research/platforms`, `POST /research/record` | Research data and experiment records. |
| `POST /test/simulate` | Deliberate test-only incident creation from a supplied diff. |

Snapshot scans, wallet verification, project incident collection, indexing and notification deliveries are queued in the database and processed by backend worker threads. Expired leases are recovered after a restart; retries are bounded, and notification delivery can be duplicated if a process stops after an external service accepts a message but before the result is saved. Optional model upgrades run as part of collection. Experiment-only revocation monitors and startup knowledge-base warming still run in process. Provider access and logging determine available evidence.

Administrators and security leads can enable **Automatic log refresh** independently on each eligible incident, selecting an interval from 15 minutes to seven days. Each schedule is disabled by default, uses the incident's project wallet reader, and skips runs if the reader is unavailable or collection is already queued or running. The incident page reports the last scheduling result, while collection failures appear in the incident. A running backend is required; overdue schedules resume after workers restart. Disabling prevents future scheduling but does not cancel already queued collections. When upgrading, an enabled legacy organisation-wide schedule is converted into independent schedules for existing eligible incidents. Provider retention, permissions, rate limits and logging configuration still limit results.

## How to interpret common outcomes

| What the operator sees | What it means or what to check |
| --- | --- |
| Snapshot result contains a key, but Monitor is empty | Add the finding explicitly from Connect, or monitor a later signed push. Snapshot additions are detection only and do not establish exposure time. |
| GitHub reports an invalid webhook signature | The delivered payload does not verify against the backend's `GITHUB_WEBHOOK_SECRET`; check the secret configured on both sides. |
| Webhook registration says the token cannot access the resource | The GitHub token lacks rights to manage hooks on that repository; manual registration or a suitably authorized token is needed. |
| Incident exists but no forensic timeline | Check tier, collection status/error, provider permissions and retention, account identity, and the exposure-based time window. Zero events is not a universal assertion of zero account activity. |
| Stripe POST request is absent from the timeline | The Events API returns state-change events, not every POST call. A POST appears only when Stripe emits an Event for the operation; read-only requests are not included. |
| Stripe rejects refresh | The project's wallet reader may be inactive, lack Events permission, use the wrong mode, or belong to a different account. Refresh cannot use a full leaked key that was intentionally not persisted. |
| Twilio `SK` key is detected without events | An owning `AC` Account SID and authorized account reader are needed; account activity cannot identify the exact API key that caused it. |
| Incident says complete | Processing finished. Confirm remediation separately; complete does not assert the credential is safe or rotated. |

## Source and related documentation

- [README.md](../README.md): setup, scope, platform coverage, and research limitations.
- [local-testing.md](local-testing.md): local operator setup and testing flow.
- [ai-detection.md](ai-detection.md): AI credential families and static recovery rules.
- [logic-review.md](logic-review.md): implementation review notes.
- [backend/routers/webhook.py](../backend/routers/webhook.py) and [backend/routers/repositories.py](../backend/routers/repositories.py): the two GitHub entry points.
- [backend/pipeline.py](../backend/pipeline.py) and [backend/routers/incidents.py](../backend/routers/incidents.py): forensic processing and incident API.

This file should be updated when incident creation rules, collection windows, provider coverage, user-visible pages, or persistence behavior change.
