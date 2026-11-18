# CODEX MASTER IMPLEMENTATION PROMPT — COMPLETE BREACHTRACE GCP FORENSICS

## ROLE AND OBJECTIVE

You are the lead backend engineer, cloud security engineer, and digital-forensics architect responsible for completing the **Google Cloud Platform (GCP) integration of BreachTrace**, an AI-assisted, multi-cloud credential exposure detection and forensic investigation platform.

**Your objective is to implement the complete, working GCP forensic pipeline within the existing repository, from GitHub credential detection through real cloud evidence collection, normalization, classification, correlation, severity assessment, incident tracking, and report generation.**

This is an existing final-year engineering research project. Do not rebuild it, replace its architecture, create a disconnected proof of concept, or use synthetic data in place of genuine evidence.

You must inspect the repository first, understand the established conventions, implement the missing GCP functionality, and integrate it with all applicable existing components.

**Do not stop after providing a plan. Make the changes, run tests, correct failures, and deliver an integrated implementation.**

Preserve existing AWS, Azure, Stripe, and Twilio functionality.

---

# PART 1 — UNDERSTAND THE EXISTING REPOSITORY

Before writing implementation code, inspect the actual project structure and identify:

1. GitHub webhook handlers and commit-diff processing.
2. Credential regex detection and validation.
3. Supported platform and credential type definitions.
4. Credential wallet and forensic-reader configuration.
5. Incident creation and tracking.
6. Exposure-window detection.
7. Existing AWS, Azure, and GCP collectors.
8. Shared audit-event normalization schemas.
9. `classifier/rules.py` and the existing impact taxonomy.
10. Severity calculations and bulk escalation.
11. Database models, migrations, and persistence.
12. Background jobs, retries, and incident lifecycle.
13. `/test/simulate`, scenario runners, and research test interfaces.
14. `backend/research/scenarios/` and `ScenarioResult`, if implemented.
15. Report generation, including any Gemini integration.
16. Dashboard APIs and frontend incident views.
17. Existing unit, integration, and end-to-end tests.

The research specification references paths such as:

- `classifier/rules.py`
- `backend/research/scenarios/gcp/`
- `backend/research/scenarios/base.py`
- `backend/research/scenarios/runner.py`
- `collectors/demo.py`
- `seed/mock_incidents.json`

These are references to the intended architecture, not guarantees about the current repository. Locate the actual corresponding modules.

**Implementation rules:**

- Reuse existing infrastructure instead of creating competing abstractions.
- Follow existing framework, naming, ORM, authentication, and routing conventions.
- Extend shared components only where genuinely necessary.
- Use migrations for persistence changes.
- Avoid breaking existing API contracts.
- Preserve backward compatibility where practical.
- Do not introduce a second parallel incident-processing pipeline.
- Use the project's existing dependency manager.
- Avoid introducing unnecessary dependencies.
- Do not hardcode cloud credentials.
- If a module is missing, implement it in the appropriate existing architectural location.

Begin by identifying the current GCP implementation, its gaps, and the specific files requiring changes. Then proceed with implementation.

---

# PART 2 — ACTUAL GCP EXPERIMENT ENVIRONMENT

We already performed real, controlled GCP operations and successfully retrieved genuine Cloud Audit Logs.

These are actual verified research results, not hypothetical samples.

## GCP environment

**Project ID:**

`breachtrace-forensics-shash`

**Project number:**

`390357551286`

**Experiment identity:**

`bt-experiment@breachtrace-forensics-shash.iam.gserviceaccount.com`

**Forensic reader identity:**

`bt-reader@breachtrace-forensics-shash.iam.gserviceaccount.com`

**Region:**

`us-central1`

**Buckets:**

- Source: `breachtrace-forensics-shash-bt-src`
- Destination: `breachtrace-forensics-shash-bt-dst`
- Protected: `breachtrace-forensics-shash-bt-protected`

The source bucket initially contained five synthetic files, `sample-1.txt` through `sample-5.txt`, each 45 bytes.

The destination bucket contains five controlled copies prefixed `bt-copy-20261118T155055Z-`.

The protected bucket contains `protected-canary.txt`, which the experiment identity cannot read.

All three buckets have public access prevention enabled.

## Authentication and IAM

The experiment identity uses **service-account impersonation**, not a downloadable private key.

The reader has:

- `roles/logging.privateLogViewer`
- `roles/serviceusage.serviceUsageConsumer`, where required by the existing CLI setup

The administrator has `roles/iam.serviceAccountTokenCreator` on each individual service account to permit controlled impersonation.

The project has Cloud Audit Logging configured with:

- `ADMIN_READ`
- `DATA_READ`
- `DATA_WRITE`
- `service: allServices`

**Important restriction:**

`constraints/iam.disableServiceAccountKeyCreation`

GCP rejects user-managed service-account JSON key creation under the current policy.

Do not bypass this policy or assume a private key exists.

Implement supported keyless authentication first.

## Verified historical experiment data

We completed **20 controlled actions producing 51 genuine Cloud Audit Log records**, divided into four scenarios.

| Scenario | UTC start | UTC end | Commands | Audit records |
|---|---|---|---:|---:|
| Reconnaissance | 2026-11-18T15:44:38Z | 2026-11-18T15:45:16Z | 5 | 6 |
| Data access | 2026-11-18T15:47:46Z | 2026-11-18T15:48:36Z | 5 | 15 |
| Controlled copying | 2026-11-18T15:50:55Z | 2026-11-18T15:51:45Z | 5 | 25 |
| Denied access | 2026-11-18T15:53:49Z | 2026-11-18T15:54:23Z | 5 | 5 |
| **Total** | | | **20** | **51** |

These windows must be supported as independent, precisely bounded investigations.

### Scenario A — Reconnaissance

Five successful CLI commands generated six audit records:

- `storage.buckets.list`: 2
- `storage.buckets.get`: 2
- `storage.objects.list`: 2

Tasks performed:

- List project buckets.
- Inspect source bucket metadata.
- Inspect destination bucket metadata.
- List source objects.
- List destination objects.

The duplicate bucket-list record must not automatically count as a second independent reconnaissance command.

### Scenario B — Data access

Five successful object-download commands generated 15 records:

- `storage.objects.get`: 10
- `storage.buckets.getStorageLayout`: 5

Each high-level download produced two object-get records and one storage-layout record.

Five distinct source objects were accessed.

This is a critical test of BreachTrace's ability to distinguish raw API requests from logical user actions.

### Scenario C — Controlled copying

Five successful source-to-destination copies generated 25 records:

- Source `storage.objects.get`: 10
- Destination `storage.objects.create`: 5
- Destination `storage.objects.list`: 5
- Destination `storage.objects.get`, status code 5: 5

The last group represents destination object lookup failures before object creation.

Status code `5` means `NOT_FOUND`.

It must not be interpreted as a permission-denied security violation.

The resulting evidence shows controlled movement of 225 bytes between private buckets belonging to the same project.

Do not report this as confirmed external exfiltration.

### Scenario D — Denied access

Five attempts to read the protected canary generated five records:

- `storage.objects.get`: 5
- Status code: `7`
- Target: `protected-canary.txt`

All attempts were denied as expected.

Status code `7` represents `PERMISSION_DENIED`.

There was no successful protected-object access.

### Common forensic attributes

The observed caller IP was:

`35.185.178.3`

The audit records identify the experiment service account as the acting principal.

The records also include `serviceAccountDelegationInfo` identifying the impersonation chain.

The IP represents observed Cloud Shell request-origin infrastructure, not independently established attacker geography.

The records do not establish misuse of a leaked JSON key or a standard `AIza` API key.

## Existing evidence files

The original files are currently stored in the GCP Cloud Shell environment:

`$HOME/bt-gcp-evidence/`

With:

- `recon-audit.json`
- `recon-ground-truth.csv`
- `data-audit.json`
- `data-ground-truth.csv`
- `copy-audit.json`
- `copy-ground-truth.csv`
- `denied-audit.json`
- `denied-ground-truth.csv`

They were exported using the real `bt-reader` identity.

These files may not be present in the local Codex workspace.

**Do not invent their contents or claim to have tested against them unless the files are actually accessible.**

Implement an importer that can consume these exact files when provided.

Use generated sanitized fixtures for unit tests where necessary, clearly distinguishing those fixtures from the real 51-record dataset.

---

# PART 3 — REQUIRED END-TO-END ARCHITECTURE

The complete production-oriented flow must be:

1. GitHub webhook receives a push event.
2. BreachTrace validates the webhook signature.
3. Commit additions are inspected for supported credentials.
4. A credential candidate is detected.
5. The credential type and associated identity/project are resolved where possible.
6. A new incident is created or an existing incident is updated idempotently.
7. The correct exposure/investigation window is established.
8. An authorized GCP reader identity collects relevant audit records.
9. Raw evidence is safely persisted.
10. Events are normalized into BreachTrace's shared forensic schema.
11. Repeated raw requests are correlated into meaningful operations.
12. Existing classification rules assign appropriate impact categories.
13. Severity and bulk escalation rules are evaluated.
14. Evidence strength and attribution confidence are calculated.
15. The incident timeline is constructed.
16. A forensic report is generated using evidence-backed facts.
17. The incident is displayed in the existing dashboard.
18. Collection and processing results are persisted with observable statuses.
19. A research evaluation compares the actual output against ground truth.
20. Errors, missing logs, and unsupported attribution are clearly disclosed.

The same core collector and analysis components must support controlled historical investigations without requiring an actual credential leak.

Do not implement historical research mode by inserting fake audit events or directly creating a completed incident.

---

# PART 4 — GCP CREDENTIAL DETECTION

Implement credential-type-aware detection.

## 4.1 Standard GCP API keys

Retain support for the existing `AIza` pattern.

An illustrative pattern is:

`AIza[0-9A-Za-z_-]{35}`

Do not replace a more accurate or better-tested pattern already present in the project without justification.

Detect candidates in added GitHub commit content.

Extract safe surrounding context when needed, but do not persist the raw credential unnecessarily.

Store:

- Platform: `gcp`
- Credential type: `gcp_api_key`
- Secret fingerprint
- Masked display value
- GitHub repository and commit identifiers
- Detection timestamp
- Exposure timestamp
- Resolution status
- Project identifier, if verified
- API key resource name, if resolved
- Known restrictions, when available

Do not interpret a regex match as proof that a key exists, is valid, or is compromised.

### API-key resolution

Where authorized and configured, use Google's API Keys API to resolve a detected key using the supported `keys.lookupKey` operation.

This may identify:

- Associated project
- API key resource identifier
- Relevant key metadata and restrictions

Use the API Keys API only with appropriate owner-side permissions.

Make lookup optional and fail safely if authorization is unavailable.

Do not expose the raw key in logs, error messages, URLs shown in the UI, or analytics.

Inspect API restrictions and application restrictions when the project owner grants appropriate access.

Never assume a standard API key identifies a service account.

**Critical rule:**

Do not correlate a leaked `AIza` API key with arbitrary GCS or IAM audit events simply because the API key and service account belong to the same project.

When exact key-specific API usage cannot be determined, return a limited, clearly labeled exposure assessment instead of fabricating credential misuse.

Support `PROJECT_ONLY` attribution when only the project can be verified.

If newer service-account-bound API-key capabilities are supported, handle them as an explicitly verified subtype. Do not assume every API key is service-account-bound.

## 4.2 GCP service-account JSON credentials

Implement detection of structurally valid service-account JSON credentials.

Look for an appropriate combination of:

- `type = service_account`
- `project_id`
- `private_key_id`
- `private_key`
- `client_email`
- `token_uri`

Handle JSON embedded in commit diffs, including multiline additions and commonly escaped representations where practical.

Avoid matching unrelated JSON objects or isolated private-key text.

Extract safe metadata:

- Project ID
- Service-account email
- Private-key ID
- Credential type
- Commit metadata
- Exposure timestamp

Do not store or send private-key material to the LLM, frontend, report, application logs, or database audit tables.

Use a deterministic keyed fingerprint for secret matching, with secret comparison performed safely.

Never use the leaked service-account private key to authenticate BreachTrace's forensic collector.

## 4.3 GitHub integration

Integrate with the existing webhook and detection workflow.

Requirements:

- Verify webhook signatures.
- Parse push events correctly.
- Support multiple commits.
- Analyze added lines without interpreting deleted credentials as newly exposed.
- Handle truncated or unavailable diffs according to existing infrastructure.
- Avoid duplicate incidents from webhook retries.
- Identify multiple credentials in one commit.
- Associate detections with repository, commit SHA, file path, and detection time.
- Avoid duplicate incident creation for repeated sightings of the same credential unless the existing design explicitly supports separate exposures.
- Redact secret values everywhere.
- Maintain compatibility with existing AWS, Azure, Stripe, and Twilio detection.
- Do not create an actual public GitHub credential leak as part of automated tests.

For testing, support synthetic fixtures and the existing private `/test/simulate` workflow.

The production webhook path and research simulation path should converge on the same investigation orchestration.

---

# PART 5 — GCP READER AUTHENTICATION

Implement an independent forensic reader.

**Never use the detected or leaked credential as the audit-log reader.**

Required authentication modes:

### Mode A — Keyless service-account impersonation

Primary development mode.

- Obtain authorized source credentials through Google Application Default Credentials.
- Use `google-auth` impersonated credentials or an equivalent supported Python authentication mechanism.
- Impersonate the configured reader service account.
- Use the temporary credentials to query Cloud Logging.
- Refresh credentials when necessary.
- Do not depend on an administrator access token being stored in project files.

Configured reader:

`bt-reader@breachtrace-forensics-shash.iam.gserviceaccount.com`

Use a configuration setting such as:

`GCP_AUTH_MODE=impersonation`

The implementation must not silently fall back to collecting logs with administrator credentials when impersonation fails.

### Mode B — Native workload identity

Support deployment using an attached service account, Workload Identity Federation, or equivalent Application Default Credentials configuration.

If BreachTrace is hosted on GCP and already runs under the appropriate reader identity, unnecessary impersonation should be avoided.

Do not assume every hosting environment supports the Cloud Shell authentication flow.

### Mode C — Explicit JSON credential wallet

Maintain optional compatibility with the project's existing GCP credential wallet if it expects an authorized reader JSON credential.

This is a compatibility mode, not the default.

- Never use the leaked experiment key as the reader credential.
- Validate the credential's identity and project configuration.
- Store credentials securely.
- Never commit a JSON private key.
- Do not require a JSON key when keyless authentication is available.

### Permissions

The collector needs read access to relevant audit logs, including Data Access logs.

Use the existing `bt-reader` permissions.

Do not automatically grant `Owner`, `Editor`, `Storage Admin`, or broad IAM administrator roles.

Document any additional permissions needed for optional API-key metadata lookup separately.

Use project allowlisting. Unauthorized project IDs must be rejected.

Provide a safe read-only authentication health check.

---

# PART 6 — IMPLEMENT THE REAL GCP AUDIT COLLECTOR

Implement a reusable Python collector that accepts, conceptually:

`collect_gcp_audit_logs(project_id, principal_email, start_utc, end_utc, options)`

Adapt this signature to the repository's actual interfaces.

## 6.1 Collection requirements

Use Google's supported Cloud Logging APIs.

Prefer the official Python client or the authenticated `entries.list` REST API.

The endpoint is:

`POST https://logging.googleapis.com/v2/entries:list`

Support:

- Explicit project ID.
- Optional verified principal email.
- Explicit UTC time boundaries.
- Inclusion of Admin Activity and Data Access logs.
- Other relevant supported audit-log types where required.
- Pagination using `nextPageToken`.
- Configurable page size.
- Deterministic ordering.
- Safe retry with exponential backoff.
- Timeouts.
- API quota failures.
- IAM permission errors.
- Ingestion-delay handling.
- Collection status and diagnostics.
- A configurable maximum investigation window.
- A configurable maximum number of records.
- Cancellation or bounded execution.
- Idempotent repeated collection.
- Clear distinction between no results and collection failure.

The collector must never silently truncate results at 100 or 500 records.

If collection is truncated due to a configured limit, report that limitation.

## 6.2 Correct filtering

Support Cloud Audit Logs associated with services such as:

- `storage.googleapis.com`
- `iam.googleapis.com`
- `iamcredentials.googleapis.com`
- `cloudresourcemanager.googleapis.com`
- `compute.googleapis.com`
- `secretmanager.googleapis.com`
- `cloudkms.googleapis.com`
- `cloudfunctions.googleapis.com`
- `run.googleapis.com`
- `pubsub.googleapis.com`
- `bigquery.googleapis.com`
- `logging.googleapis.com`
- Relevant Cloud Billing/Budget services where supported

The exact service names and logged method names must be verified against Google's documentation and real payloads.

Do not assume that merely enabling a GCP API guarantees every operation generates an audit log.

The query must support filtering by:

- Project
- Time window
- Principal email, when meaningful
- Service name
- Method name
- Resource name
- Result status

For service-account JSON investigations, filter by the service-account principal and then inspect available key-level evidence.

For standard API keys, do not force a service-account principal filter when no corresponding principal exists.

## 6.3 Audit logging prerequisites

Include a configuration check for:

- Cloud Logging API availability.
- Storage Data Access logging.
- `ADMIN_READ`, `DATA_READ`, and `DATA_WRITE`, where relevant.
- Exempted principals.
- Reader permissions.

In our project, the audit configuration is:

`service: allServices`

with all three permission categories enabled.

Support inherited audit configuration where possible, rather than incorrectly requiring separate service-specific settings.

When auditing is disabled or unavailable, report an evidence-collection limitation.

Do not interpret empty logs as proof that no suspicious activity occurred.

## 6.4 Retrieval and pagination

Collect all records within the requested window up to configured limits.

Store:

- Records received
- Pages retrieved
- Collection start time
- Collection finish time
- Last successful page
- Errors
- Partial completion
- Evidence source
- Any unresolved collection gaps

Support reopening and refreshing an investigation when additional audit records arrive.

Implement appropriate UTC comparisons, including timestamps with nanosecond precision.

Keep timestamp handling timezone-aware.

---

# PART 7 — NORMALIZE GCP FORENSIC EVIDENCE

Map raw GCP audit entries into BreachTrace's existing normalized event model.

Reuse the project's shared schema.

Extend it only when required for real evidence.

## Required fields

Capture, where available:

- Event/record identifier
- Platform
- Project ID
- Service name
- API method name
- Original method name
- Normalized action name
- Event timestamp
- Collection timestamp
- Acting principal email
- Principal subject
- Service-account delegation information
- Service-account key name
- Caller IP
- User agent
- Resource name
- Resource type
- Source resource
- Destination resource
- Operation identifier
- Request/correlation identifier
- Authorization status
- Status code
- Status message
- Log name
- Ingestion/receive timestamp, if available
- Raw evidence reference
- Credential attribution level
- Impact category
- Severity
- Classification explanation

Preserve original method names instead of overwriting them with friendly labels.

## 7.1 Result status semantics

Correctly interpret:

- Missing or empty `protoPayload.status`: successful operation when consistent with the audit record.
- Code `0`: success.
- Code `5`: `NOT_FOUND`.
- Code `7`: `PERMISSION_DENIED`.

Handle other canonical status codes correctly.

Do not equate every nonzero status with a security violation.

A failed read, an ordinary missing resource, and a successful privileged operation have different forensic meanings.

## 7.2 Identity attribution

Extract:

`protoPayload.authenticationInfo.principalEmail`

`protoPayload.authenticationInfo.serviceAccountKeyName`

`protoPayload.authenticationInfo.serviceAccountDelegationInfo`

Also support alternative principal identifiers when available.

Implement explicit attribution levels:

- `EXACT_KEY` — trustworthy evidence identifies the particular exposed service-account key.
- `PRINCIPAL_LEVEL` — activity matches the service account, but not necessarily the particular key.
- `PROJECT_LEVEL` — only project association is supported.
- `UNATTRIBUTED` — insufficient evidence for reliable linkage.

Exact key attribution must use a verified key identifier when recorded.

Do not invent `serviceAccountKeyName` when it is absent.

Our 51 historical events should be treated as principal-level research evidence, with impersonation details preserved.

Because no JSON key was used, those events must not receive `EXACT_KEY` attribution.

## 7.3 Caller IP

Extract the observed caller IP without performing unsupported identity or geolocation inference.

Do not automatically classify a Cloud Shell IP as a malicious attacker IP.

Support missing, private, proxied, or otherwise uninformative IP values.

## 7.4 Safe raw-evidence handling

Persist raw or minimally transformed evidence in the existing evidence store when authorized.

Provide references from normalized records back to original audit entries.

Avoid unnecessary retention of sensitive request payloads.

Redact credentials and secrets.

Store evidence integrity hashes where appropriate.

Support repeatable, idempotent imports and avoid modifying source evidence.

---

# PART 8 — EVENT DEDUPLICATION AND LOGICAL ACTION CORRELATION

**This is a mandatory research-critical feature.**

Our experiments established that one CLI command may create several separate audit records.

You must implement two distinct concepts.

## 8.1 Raw-record deduplication

Prevent duplicate ingestion of the same actual audit record during repeated collections.

Prefer stable identifiers such as a combination of project, log name, and `insertId` where available.

Use a carefully defined fallback fingerprint when necessary.

Never collapse distinct audit records merely because they have the same method, resource, and timestamp rounded to seconds.

## 8.2 Logical-action correlation

Group multiple distinct API records that belong to one higher-level command or operation.

Potential signals include:

- `operation.id`
- Request/correlation IDs
- CLI invocation identifiers in user-agent text
- Principal
- Source IP
- Resource name
- Related method names
- Small time windows
- Expected operation sequence

Our `gcloud` audit records contain `invocation-id` values in the caller-supplied user agent.

Use these when present, but don't assume every client or service supplies them.

Maintain both raw and logical counts.

For example:

**Five actual downloads produced ten `storage.objects.get` records.**

Expected analytical results:

- Raw object-get records: 10
- Distinct target objects: 5
- High-confidence logical downloads: 5, if the request evidence supports grouping

The system must retain all ten raw records.

Do not delete forensic evidence merely because multiple records are associated with one logical operation.

## 8.3 Correlating controlled copying

Identify the pattern:

- Source-object reads
- Destination-object existence checks
- Destination listing
- Destination object creation

Group related records by operation when sufficiently supported.

Expose:

- Source bucket
- Destination bucket
- Source object
- Destination object
- Success/failure
- Observed timestamps
- Evidence record IDs
- Correlation confidence

For our experiment, there should be five successful controlled copying operations.

The destination `NOT_FOUND` checks are not unauthorized reads.

Do not label them privilege escalation or confirmed exfiltration.

The final destination objects belong to the same project.

## 8.4 Confidence and ambiguity

Use strong correlation signals before inferring a logical operation.

If identifiers are missing, do not aggressively combine unrelated events merely because their timestamps are close.

Represent uncertainty explicitly.

Maintain a clear separation between:

1. Raw API audit records.
2. Deduplicated unique audit records.
3. Correlated logical operations.
4. Classified incident findings.

---

# PART 9 — GCP CLASSIFICATION AND TAXONOMY

Integrate the real GCP events with the existing `classifier/rules.py` and severity system.

The research plan specifies eight GCP impact categories:

1. `reconnaissance`
2. `data_access`
3. `exfiltration`
4. `resource_abuse`
5. `privilege_escalation`
6. `financial_abuse`
7. `communication_abuse`
8. `code_compromise`

It additionally specifies bulk escalation from repeated data access to suspected exfiltration.

Do not create another incompatible classifier or replace existing category definitions.

## 9.1 Reconnaissance

Support applicable method mappings for:

- Cloud Storage bucket listing and metadata
- IAM service-account listing
- Compute instance enumeration
- Project metadata reads
- Other reconnaissance rules already present

For the verified dataset, correctly recognize `storage.buckets.list`, `storage.buckets.get`, and `storage.objects.list`.

## 9.2 Data access

Support:

- `storage.objects.get`
- Secret Manager secret-version access
- Cloud KMS decrypt operations
- Other supported data-access operations

Use actual logged method names and existing aliases.

Differentiate successful data access from denied attempts.

## 9.3 Exfiltration-like activity

Support existing taxonomy rules for:

- Cloud Storage object copying
- BigQuery exports
- Compute snapshot operations
- Relevant log sink changes

But assess context.

A `storage.objects.create` event alone is not proof of exfiltration.

Inspect source/destination relationships where possible.

Distinguish:

- Confirmed controlled internal movement
- Suspicious movement
- External destination with supporting evidence
- Insufficient evidence

Use the project's existing `exfiltration` impact category where applicable, but ensure the narrative distinguishes suspicion from proven data theft.

Do not automatically assign Critical severity to any object copy.

## 9.4 Resource abuse

Support existing rules for operations such as:

- VM creation
- Firewall changes
- Bucket creation/deletion
- Other potentially abusive resource actions

Distinguish successful execution from failed attempts.

Do not assume expensive resources were provisioned unless the audit outcome confirms success.

## 9.5 Privilege escalation

Support existing rules for:

- IAM policy modification
- Service-account key creation
- Service-account creation
- Service-account signing operations
- Other relevant IAM privilege changes

A denied IAM policy update is an attempted operation, not successful privilege escalation.

Use actual GCP audit method names and correct API-specific aliases.

## 9.6 Code compromise

Support relevant Cloud Run and Cloud Functions changes, including create/update/deployment operations where observable.

Do not assume a deployment occurred when the API request failed.

## 9.7 Communication abuse

Support Pub/Sub administration and applicable publish-related evidence.

Some Pub/Sub operations may not emit the expected Data Access records.

Record observability limitations instead of manufacturing events.

## 9.8 Financial abuse

Support existing billing/budget-related taxonomy rules.

A budget update is not automatically financial abuse.

Use observed context and status.

Do not trigger real chargeable actions as part of automated tests.

## 9.9 Unrecognized methods

Preserve unknown operations as observed but unclassified.

Do not silently discard them.

Report taxonomy coverage separately from collection coverage.

Use the existing shared taxonomy and rule identifiers wherever possible.

---

# PART 10 — BULK ACCESS ESCALATION

The research specification defines:

`GCP-BULK-01`

Repeated `storage.objects.get` activity from one caller IP crosses a threshold of five and may escalate from `data_access` to `exfiltration`.

Implement this in the existing bulk-escalation mechanism.

## Mandatory requirements

- Group activity within an explicitly defined time window.
- Use verified principal and IP information where available.
- Count raw events separately from logical actions.
- Make the threshold configurable.
- Avoid accidental inflation from duplicate ingestion.
- Handle multiple API reads generated by one CLI command.
- Preserve the exact records triggering the rule.
- Record whether the rule matched raw-event or logical-action counts.
- Store the triggering count and threshold.
- Display the finding as suspected exfiltration, not confirmed theft.
- Allow contextual evidence to lower or qualify severity.

Our test data contains:

- 5 intentional downloads
- 10 corresponding raw object-get records
- 5 unique source objects
- One observed caller IP

The system should recognize the threshold and explicitly demonstrate whether raw-event counting would have produced premature escalation.

Do not hide this discrepancy.

Use it as part of the project's forensic reliability evaluation.

---

# PART 11 — EXPOSURE WINDOWS AND CREDENTIAL CORRELATION

The credential detector and forensic collector must share a coherent exposure-window model.

For a genuine detected credential:

- Record the earliest confirmed appearance in the monitored repository.
- Track subsequent relevant appearances if supported.
- Record known revocation or exposure-end evidence.
- Use configurable investigation lookback and forward windows.
- Distinguish pre-exposure, during-exposure, and post-revocation activity.
- Preserve UTC precision.
- Handle delayed audit-log ingestion.

Never claim that activity occurring before the credential leak was caused by that leak.

## Research historical mode

Create an explicit research mode for investigating known activity using:

- Project ID
- Principal email
- UTC start/end
- Research scenario identifier

This mode must invoke the real collector, normalizer, classifier, and report pipeline.

It must not require inventing a GitHub leak.

It must be labeled:

`research_forensic_evaluation`

or a compatible existing mode.

The four historical experiment windows must be importable and analyzable through this path.

## Attribution strength

For a service-account JSON leak:

1. Attempt exact key matching when trustworthy key-name evidence is available.
2. Otherwise correlate at service-account principal level.
3. Clearly disclose when evidence cannot distinguish multiple keys or impersonation from actual key use.

For a standard API-key leak:

1. Verify project/key metadata when possible.
2. Investigate only supported key-specific telemetry.
3. Do not infer service-account compromise merely from project membership.
4. Present unrelated or insufficiently attributed project events as context, not confirmed key misuse.

This attribution model must flow into incident scoring and report generation.

---

# PART 12 — INCIDENT LIFECYCLE AND ORCHESTRATION

Connect GCP to the existing BreachTrace incident workflow.

Reuse its state machine where possible.

Support meaningful states such as:

- detected
- validation_pending
- validated
- investigation_pending
- collecting
- normalizing
- classifying
- reporting
- complete
- partial
- failed
- unsupported

Adapt to existing status naming.

Do not mark incidents complete merely because a background task was successfully queued.

Persist:

- Incident ID
- Platform
- Credential type
- Credential fingerprint
- Detection source
- Project
- Principal
- Exposure window
- Collection status
- Evidence count
- Logical action count
- Classification results
- Severity
- Attribution confidence
- Processing errors
- Report reference
- Timing metrics

Ensure jobs can be retried without duplicating incident evidence.

Preserve deterministic behavior for repeated investigations.

Use the project's existing queue or background processing mechanism.

Do not block GitHub webhook delivery while waiting for Cloud Logging ingestion or report generation.

---

# PART 13 — DATABASE AND FORENSIC EVIDENCE PERSISTENCE

Inspect the existing schema before creating tables or fields.

Add only necessary schema changes.

Required persistence concepts include:

- Credential detection metadata
- Project/reader configuration reference
- Investigation windows
- Raw audit-log references
- Normalized forensic events
- Logical operation groups
- Classification outcomes
- Evidence attribution levels
- Incident findings
- Collection runs
- Research experiment runs
- Report references

Use stable unique identifiers.

Guarantee idempotent ingestion.

Provide indexes for commonly used queries:

- Incident ID
- Platform/project
- Principal
- Event timestamp
- Credential fingerprint
- Event type
- Evidence ID
- Classification category

Avoid storing plaintext secrets.

Do not store access tokens.

Use migrations consistent with the current database technology.

---

# PART 14 — DASHBOARD AND API INTEGRATION

Integrate GCP evidence into the existing dashboard rather than creating a separate application.

Inspect the existing UI components and API response models.

Implement or extend views for:

## Incident summary

Show:

- Platform: GCP
- Incident source
- Credential type
- Project ID
- Associated principal, if verified
- Detection time
- Investigation window
- Severity
- Current status
- Attribution confidence
- Evidence coverage
- Findings summary

## Timeline

Show chronological events with:

- UTC timestamp
- Human-readable operation
- Original API method
- Principal
- Resource
- Source IP
- Outcome
- Severity
- Impact category
- Evidence reference

Differentiate successful, denied, and not-found operations.

Support grouping correlated raw events into logical actions while allowing the investigator to inspect the underlying audit records.

## Evidence panel

Show:

- Raw records
- Unique raw records
- Logical operations
- Findings
- Collection gaps
- Attribution strength
- Source/destination relationships

The interface must not display an incident as empty when genuine records have been collected.

## Research mode

Show that the historical GCP evaluation contains:

- 20 ground-truth commands
- 51 real audit records
- Four scenarios
- Five controlled copying operations
- Five denied-access attempts
- Multiple CLI-generated API records per logical action

Mark these as historical forensic research results, not a confirmed credential theft incident.

If the frontend already supports similar AWS or Azure displays, reuse those components.

---

# PART 15 — FORENSIC REPORT GENERATION

Connect normalized GCP evidence to BreachTrace's existing report-generation pipeline.

If Gemini is used, the model should receive a carefully selected structured evidence summary, not unrestricted raw logs or secrets.

## Report requirements

Generate:

1. Executive summary.
2. Detection source and credential type.
3. Credential exposure details.
4. GCP project and principal details.
5. Investigation time boundaries.
6. Relevant services.
7. Chronological forensic timeline.
8. Reconnaissance findings.
9. Data-access findings.
10. Data-movement findings.
11. Denied-access findings.
12. Other taxonomy findings where evidence exists.
13. Bulk-access threshold assessment.
14. Severity and rationale.
15. Evidence attribution confidence.
16. Source IP observations.
17. Affected resource names.
18. Data volume, only if supported by evidence.
19. Collection completeness and limitations.
20. Recommended remediation.
21. Evidence references.

## Hard evidence requirements

The AI must not:

- Claim a standard API key authenticated GCS IAM operations without evidence.
- Claim exact-key attribution when `serviceAccountKeyName` is absent.
- Describe internal bucket copies as confirmed external exfiltration.
- Claim that code-7 requests succeeded.
- Treat code-5 destination lookups as unauthorized access.
- Invent attacker identity, origin country, motivation, or stolen data.
- Invent services or resources not present in evidence.
- Claim all eight incident categories were experimentally validated when only four Storage scenarios were executed.
- Claim the private key was leaked when the experiment used impersonation.
- Claim a collector passed live testing when only mocked tests ran.

Prefer deterministic, evidence-derived report facts, with the language model providing explanation and readable synthesis.

Every major finding should reference evidence IDs.

Include an explicit **Limitations and Confidence** section.

Generate project-correct GCP remediation guidance, not generic AWS commands.

---

# PART 16 — RESEARCH SCENARIO INTEGRATION

Integrate with the existing research scenario framework.

The original plan references:

- `ScenarioResult`
- `record_run`
- `experiment_runs`
- `research/scenarios/runner.py`

Preserve existing interfaces if present.

## GCP scenario identifiers

Support the research taxonomy identifiers:

- `GCP-RECON-01`
- `GCP-DATA-01`
- `GCP-EXFIL-01`
- `GCP-ABUSE-01`
- `GCP-PRIVESC-01`
- `GCP-CODE-01`
- `GCP-COMM-01`
- `GCP-FIN-01`
- `GCP-BULK-01`

The verified historical Storage dataset should be mapped to suitable research scenario records, without falsely claiming that all nine scenarios have run live.

The copied-object scenario should be labeled a controlled data-movement simulation.

Where scenario execution is unavailable, support an explicit `not_executed`, `unsupported`, or `expected_blind` result, rather than creating fabricated success records.

## Research runner

Provide an interface consistent with the existing CLI to:

- Run historical evidence collection.
- Import provided evidence files.
- Compare against ground truth.
- Execute classification.
- Generate an evaluation result.
- Generate a report.
- Re-run idempotently.
- Store experiment metrics.

Do not execute cloud mutations automatically.

Do not launch compute resources during the normal test suite.

Real cloud scenarios must be explicitly opt-in.

---

# PART 17 — GROUND-TRUTH EVALUATION

Implement a reproducible evaluation module using the CSV and JSON research files.

Ground truth and audit logs must remain independent evidence sources.

## Required evaluation metrics

### Collection

- Expected observed audit records
- Retrieved audit records
- Missing audit records
- Duplicate ingestion
- Collection completeness
- Pagination completeness

### Correlation

- Ground-truth commands
- Raw audit records
- Distinct resources
- Logical operations
- Correctly grouped operations
- Incorrectly grouped operations
- Uncertain correlations

### Classification

- Correct classification
- Incorrect classification
- Unknown classification
- Per-class precision and recall when labels are available
- Confusion matrix when meaningful
- Severity agreement
- False-positive findings

### Identity

- Principal match
- Key match where available
- Delegation detection
- Source-IP consistency
- Attribution confidence

### Timing

- API event timestamp
- Ground-truth command timestamp
- Log receipt timestamp where present
- Collector ingestion timestamp
- Classification completion timestamp
- Report completion timestamp

Distinguish actual measured pipeline latency from event age at the time of historical collection.

Do not report live detection latency using a retrospective collection as though BreachTrace detected the event immediately.

## Expected historical counts

| Scenario | Commands | Audit records |
|---|---:|---:|
| Recon | 5 | 6 |
| Data | 5 | 15 |
| Copy | 5 | 25 |
| Denied | 5 | 5 |

Expected aggregate:

- 20 commands
- 51 audit records
- 15 successful commands
- 5 intentionally denied commands
- 5 successful logical downloads
- 5 successful logical copies
- 5 denied protected-object reads

The implementation must verify the exact audit-record totals against the actual supplied files.

The expected values must not be used to fabricate missing records.

---

# PART 18 — AUTOMATED TEST SUITE

Write comprehensive tests consistent with the current testing framework.

At minimum, cover the following.

## Credential detector tests

- Valid `AIza` candidate.
- Invalid/partial `AIza` string.
- Valid service-account JSON structure.
- Incomplete service-account JSON.
- Multiline GitHub diff.
- Multiple credentials in one commit.
- Deleted lines versus added lines.
- Duplicate webhook delivery.
- Redaction of all private-key values.
- No accidental credential logging.
- Unauthorized project resolution.
- API key without service-account attribution.

## Authentication tests

- Successful reader impersonation.
- Expired token refresh.
- Missing Token Creator permission.
- Missing Private Logs Viewer permission.
- Unsupported authentication configuration.
- Wrong project.
- Reader and experiment identities accidentally matching.
- No administrator fallback.
- JSON credential-wallet compatibility, where implemented.

## Collector tests

- Correct project and timestamp filtering.
- Successful API response.
- Empty response.
- Pagination across multiple pages.
- Duplicate pages/retries.
- API timeouts.
- `429` and transient server failures.
- Permission-denied collector requests.
- Late-arriving records.
- Partial collection and safe continuation.
- Record limits.
- UTC and nanosecond timestamp handling.
- Multiple audit-log categories.
- Unsupported API audit visibility.
- No secret exposure in exception messages.

## Normalizer tests

- `storage.objects.get`
- `storage.objects.list`
- `storage.buckets.list`
- `storage.buckets.get`
- `storage.buckets.getStorageLayout`
- `storage.objects.create`
- Status code `5`
- Status code `7`
- Missing status object
- Missing caller IP
- Delegation information
- Exact service-account key name
- Missing service-account key name
- Alternate principal identifiers
- Unknown GCP method
- Missing optional metadata
- Proper raw evidence references

## Deduplication and correlation tests

- Two object-get records from one CLI invocation.
- Two independent reads of the same object.
- Duplicate ingestion of the same audit record.
- Multiple records with identical rounded timestamps.
- Copy-source reads grouped with destination creation.
- Destination `NOT_FOUND` prechecks.
- Copying across buckets in the same project.
- Missing invocation IDs.
- Conflicting correlation evidence.
- Five logical reads versus ten raw object-get records.
- Correct handling of repeated denied requests.

## Taxonomy tests

Cover all eight GCP impact categories with representative verified method mappings and proper success/failure semantics.

Where a service has an audit blind spot, test the `expected_blind`/unsupported behavior.

## Integration tests

Use mocked Google APIs and a controlled test database to verify:

- GitHub detection → incident creation.
- Credential type resolution.
- Independent reader authentication.
- Log collection.
- Normalization.
- Classification.
- Bulk escalation.
- Evidence persistence.
- Report generation.
- Dashboard API response.
- Repeated collection without duplicates.
- Correct incomplete/failed states.

No real GCP credentials should be required for the ordinary test suite.

## Real evidence regression

When the actual four JSON files are available, add a controlled regression test ensuring that the collector's historical processing can reproduce:

- 6 reconnaissance records
- 15 data-access records
- 25 copy records
- 5 denied-access records

This regression must use the real supplied files, not fabricated equivalents.

---

# PART 19 — SECURITY AND COST RESTRICTIONS

This is a disposable, low-cost research project.

Do not create chargeable compute resources during implementation or testing.

Do not create:

- Compute Engine VMs
- GKE clusters
- Cloud NAT gateways
- Expensive BigQuery jobs
- Persistent Cloud Run services
- Production resources
- Unrestricted public buckets

Do not modify or delete the existing GCP evidence buckets.

Do not create or upload real sensitive data.

Do not disable organization policies.

Do not attempt to bypass `iam.disableServiceAccountKeyCreation`.

Do not create broad administrator IAM bindings.

Do not retrieve or expose real private keys.

Do not commit credentials to Git.

Do not submit real private keys to a public repository for testing.

Use read-only collection by default.

Any experimental cloud mutation must require an explicit live-testing flag and must not be performed automatically by tests or deployment.

Include configurable limits for:

- Allowed projects
- Investigation duration
- Maximum records
- Retry attempts
- API calls
- Historical backfill size

Ensure the implementation remains compatible with a very small GCP budget.

---

# PART 20 — CONFIGURATION AND DOCUMENTATION

Provide a documented GCP configuration section in the existing environment example and README.

Suggested settings, adapted to the repository's conventions:

- `GCP_ENABLED`
- `GCP_AUTH_MODE`
- `GCP_PROJECT_ID`
- `GCP_READER_SERVICE_ACCOUNT`
- `GCP_ALLOWED_PROJECT_IDS`
- `GCP_MAX_INVESTIGATION_HOURS`
- `GCP_MAX_LOG_ENTRIES`
- `GCP_API_KEY_LOOKUP_ENABLED`
- `GCP_LIVE_TESTS_ENABLED`
- `GCP_RESEARCH_MODE_ENABLED`

Do not overwrite existing equivalent variables.

Use `GOOGLE_APPLICATION_CREDENTIALS` only where an authorized credential-file workflow is appropriate.

Do not require a private JSON key for the keyless reader workflow.

Document:

1. GCP prerequisites.
2. Required APIs.
3. IAM permissions.
4. Data Access logging setup.
5. Reader authentication.
6. API-key detection and limitations.
7. Service-account JSON detection.
8. Historical research mode.
9. Real-time incident mode.
10. Evidence import.
11. Test commands.
12. Expected dashboard output.
13. Error troubleshooting.
14. Credential revocation procedures.
15. Limitations of exact-key attribution.
16. GCP billing and safety considerations.

Use Google's official documentation as the authoritative reference.

Useful starting references:

- Cloud Audit Logs: https://docs.cloud.google.com/logging/docs/audit
- Cloud Logging entries.list: https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
- Cloud Storage audit logging: https://docs.cloud.google.com/storage/docs/audit-logging
- IAM service-account audit examples: https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts
- API Keys lookupKey: https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey
- Cloud Logging IAM roles: https://docs.cloud.google.com/logging/docs/access-control

Verify API behavior and method names against the current documentation.

---

# PART 21 — IMPLEMENTATION EXECUTION ORDER

Follow this order while working in the repository.

### Stage A — Repository audit

Inspect the code and identify existing interfaces.

Record the actual implementation gaps.

### Stage B — Credential awareness

Complete `AIza` handling and structured service-account JSON detection.

Integrate both with the existing GitHub detection pipeline.

### Stage C — Authentication

Implement safe keyless GCP reader authentication and optional existing credential-wallet compatibility.

### Stage D — Collector

Complete Cloud Logging collection with UTC filtering, pagination, retries, and explicit failure handling.

### Stage E — Normalization

Map real GCP records into the existing event schema.

### Stage F — Evidence correlation

Implement raw-record deduplication, logical-action grouping, resource matching, status semantics, and attribution levels.

### Stage G — Classification

Complete the GCP taxonomy mappings and bulk escalation.

### Stage H — Incident processing

Connect the collector to incident lifecycle, background jobs, persistence, and reports.

### Stage I — Frontend

Expose GCP incidents and their evidence through existing dashboard components.

### Stage J — Research evaluation

Implement the historical four-scenario evaluation using our actual exported evidence files when available.

### Stage K — Tests and documentation

Run all relevant tests, correct failures, update documentation, and verify that other platforms remain functional.

Do not simply create empty modules or leave `TODO` stubs in place of core behavior.

---

# PART 22 — DEFINITION OF DONE

GCP forensics is complete only when the following criteria are met.

## Detection

- Existing GitHub scanning supports GCP API-key detection.
- Structured service-account JSON detection is implemented.
- Credentials are appropriately redacted.
- Different credential types lead to different attribution logic.

## Collection

- GCP collector authenticates independently as an authorized reader.
- Data Access and Admin Activity logs are supported.
- Explicit historical windows work.
- Pagination and retry logic work.
- Partial and failed collections are reported accurately.
- No leaked credential is used as a forensic reader.

## Forensics

- Raw events are normalized.
- Actual status codes are interpreted correctly.
- Principal and delegation information are extracted.
- Exact-key attribution is used only when verified.
- Logical operations are correlated without deleting evidence.
- Copying and denied requests are differentiated.
- All eight GCP taxonomy classes are supported by the rule system, subject to genuine evidence availability.
- Bulk escalation uses an explicit counting model.
- Every finding has evidence.

## Integration

- Incidents are persisted.
- The pipeline runs through the established orchestration.
- Reports are generated.
- Dashboard data is available.
- Errors are visible.
- Research and genuine credential-exposure modes remain clearly distinguishable.

## Research validation

- All 20 ground-truth actions are represented.
- All 51 real records are importable when files are supplied.
- Correct raw-record totals are maintained.
- Duplicate object reads do not silently inflate logical-action counts.
- Five controlled copying operations are recognized.
- Five protected-object denials are recognized.
- Classification and report results can be compared with ground truth.
- No fabricated metrics or evidence are reported.

## Security

- No private keys are committed.
- No organization policies are bypassed.
- No unauthorized resource creation occurs.
- Reader and experiment identities remain separate.
- No raw credentials appear in reports or logs.
- Normal tests have no cloud billing side effects.

---

# PART 23 — FINAL DELIVERY FROM CODEX

After implementing everything possible in the available repository, provide:

**1. Architecture summary**

Explain how the completed GCP pipeline works from GitHub detection to forensic reporting.

**2. Files changed**

List every created or modified file and explain its role.

**3. Implemented functionality**

Clearly distinguish implemented features from planned or unsupported features.

**4. Authentication design**

Explain keyless reader authentication and how the existing wallet is supported, if applicable.

**5. Credential attribution**

Explain the separate behavior for standard API keys and service-account JSON credentials.

**6. GCP classification**

Summarize supported taxonomy rules and their evidence requirements.

**7. Deduplication**

Explain how BreachTrace handles the five downloads generating ten `storage.objects.get` records.

**8. Research evaluation**

Report measured results against the real 51-event dataset if it is available. Otherwise explain exactly how to supply it and execute the evaluation.

**9. Tests**

List test commands, actual pass/fail counts, and any unresolved failures.

**10. Execution instructions**

Provide the precise commands to:

- Start BreachTrace.
- Configure GCP authentication.
- Validate reader access.
- Import the four historical datasets.
- Run an investigation.
- Inspect classifications.
- Generate the report.
- View the results in the dashboard.
- Run the complete test suite.

**11. Security review**

Confirm that no raw credential or unsafe configuration was introduced.

**12. Remaining blockers**

Identify only genuine external blockers, such as missing Cloud Shell evidence files, missing deployment credentials, unavailable API permissions, or the GCP key-creation organization policy.

Do not misrepresent these blockers as implementation failures.

---

# FINAL INSTRUCTIONS

You are expected to **implement the actual GCP integration**, not merely produce pseudocode or a high-level design.

Prioritize working code, correct security assumptions, evidence preservation, and compatibility with the existing project.

Do not invent backend routes, model fields, or file paths without inspecting the repository.

Do not fabricate successful tests, GCP logs, key attribution, or research results.

Do not modify AWS, Azure, Stripe, or Twilio unnecessarily.

Do not weaken security to make the demo succeed.

When the 51-record dataset is available, the final implementation should be able to ingest and analyze those real events through the same forensic pipeline used by live investigations.

When it is unavailable, complete all code and mock-based testing possible, provide the exact import procedure, and clearly state what remains to be verified.

**Proceed through repository inspection, implementation, integration, testing, and documentation. Do not stop at an implementation plan. Deliver the most complete working GCP forensic system possible in this coding session.**