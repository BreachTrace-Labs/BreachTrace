# GCP implementation progress

The plan in `gcp.md` describes a multi-stage integration. Work below builds on the existing pipeline; the experiment counts in that document are reported by the operator and have not been verified against the original evidence files in this workspace.

## Existing implementation

- Signed GitHub push detection and the existing incident/background-job pipeline.
- Context-based service-account email detection and generic Google API-key candidates; API-key matches do not prove service-account attribution.
- A project wallet with service-account JSON readers, a Cloud Audit Logs collector, classification, timeline, reports and operator-associated key-name comparison.

## First increment: keyless reader

The wallet now supports a project ID and reader service-account email for ADC-based impersonation. The same reader factory is used by wallet verification and the existing collector; explicit JSON credentials remain supported. Only admins and security leads can configure impersonation. Missing source credentials or impersonation failures fail the connection rather than falling back to the ADC source identity. This increment does not require or create a service-account private key and does not bypass organization policy.

The original Cloud Shell evidence files are not in the repository. The code has not yet been validated against the reported 51 records or live impersonation. ADC, IAM Credentials API access and authorized roles must be configured on the backend host first. A snapshot of current limitations remains in `exposure-attribution.md`.

## Second increment: distinguish structured keys from identifiers

The existing diff and repository scanner now recognizes complete service-account JSON documents using fields from the same object. Added key fields can trigger a finding even when the email is unchanged. Identity-only and incomplete matches remain visible as detection-only observations; they do not establish private-key exposure or start forensic collection. A nearby key ID is no longer automatically attached to a different account. Parsed private-key material is not retained in the match. This is structural recognition, not validation that the credential is usable or that an exposure has been exploited.

The existing Google API-key candidate detector remains separate and detection-only; an `AIza` match does not establish a service-account identity. Incomplete or unsupported encoded material may require manual review.

## Third increment: incident key metadata

New signed GitHub-push and simulation incidents created from a structured service-account document retain its project ID and a digest and masked hint of its key ID. They use the existing event key-comparison feature, and the incident view distinguishes a commit detection, a simulation and a manually reported association. The raw private key is not persisted. The detected metadata is sourced from the document, not verified with Google; matching key-name evidence does not by itself prove abuse.

Existing manual associations are retained by the migration, and an administrator or security lead may replace a detected association with a manually reported one. The change requires migration `cc84e119d320` for Alembic-managed databases. ORM-created local databases require a separately assessed schema upgrade; see `RUNNING.md`. Existing incidents are not retroactively updated.

The detector also recognizes a complete service-account document encoded as a single JSON string in an added line. It parses one bounded JSON literal and then the contained JSON object without executing code. Removed and unchanged encoded strings do not initiate a finding. Nested encodings, split literals and encoded arrays are not supported; incomplete documents do not establish a private-key exposure. Synthetic tests exercise both simulation and signed webhook processing; recognition does not prove the credential is valid.

## Fourth increment: bounded GCP collection

The existing project-scoped Cloud Logging collector now validates the service-account principal and time range, preserves microseconds in UTC query bounds, requests ordered pages, and enforces configurable constructor limits (defaults: 90-day maximum query window, 500 entries per page, 100,000 entries per attempt). An additional entry beyond the limit fails the attempt instead of reporting a partial timeline as complete. Provider failures encountered during iteration also fail the attempt, without persisting the partial result. Authentication, quota and limit errors are recorded through the existing collection-status pipeline without exposing provider error bodies.

The incident pipeline currently requests at most the last 30 days, not an arbitrary historical range. A successful query or empty result does not verify Data Access log configuration, retention or completeness. The current high-level Google client call does not provide an explicit per-request timeout here; page diagnostics, historical mode, log-configuration checks, partial-result persistence and live-account validation remain outstanding. Limits are constructor parameters, not yet exposed in application settings. No Google API-key candidate is treated as a service-account principal.

## Fifth increment: GCP outcome and evidence handling

GCP audit status now treats an absent or empty status and code 0 as success, and codes 1–16 as failures; malformed nonempty statuses fail collection rather than being guessed. Code 7 is identified as permission denied when new events are stored and when older events are viewed. Code 5 and other failures are not labelled as denials. The timeline and analytics distinguish failed operations from specifically denied ones.

The collector retains selected authentication and authorization evidence and available log-entry identifiers, receive time and operation metadata; arbitrary request and response bodies are omitted for newly collected events. Existing key-name attribution continues to use the same authentication fields. Redaction covers recognizable Google API keys as well as the previously supported credential patterns. Refreshing an incident collects a new minimized version; this change does not retroactively sanitize existing database records.

The generic same-IP bulk heuristic no longer labels GCP reads as exfiltration. A dedicated GCP bulk-access and logical-operation analysis remains outstanding.

## Sixth increment: outcome-aware GCP impact

Failed GCP operations remain visible as attempts but no longer contribute to completed-impact severity, financial calculations or resource-based compliance flags. Successful GCP operations continue to contribute. Report fact sheets separate failed attempts from successful impact, and deterministic reports explicitly describe all-failed activity. For GCP incidents containing failed operations, the pipeline retains its deterministic report because the current model-output validator cannot reliably establish whether generated prose distinguishes attempts from completed actions.

Previously stored severity and report text are not automatically rewritten. An authorized operator can refresh an incident to recollect evidence and regenerate the report; refresh replaces its collected history and therefore still depends on provider retention and access.

## Seventh increment: GCP financial evidence

Removed the GCP estimates that assumed machine sizes, transfer volumes and rates from audit method names. The financial panel now explains that Cloud Audit Logs are not a billing feed; it does not present missing amounts as zero cost. New deterministic report text and model fact sheets carry the same limitation. Existing GCP financial-summary fields are suppressed in the incident detail, and the page and PDF warn that older saved report text may still contain unsupported estimates. Stored reports are not rewritten; a refresh regenerates them, subject to log availability. Cloud Billing is not integrated, so actual charges and incident-attributable loss remain unknown.

## Eighth increment: raw-record identity

GCP records with a log name, insert ID and full timestamp receive a deterministic source-record digest. The collector suppresses repeats within an attempt, and incident storage avoids inserting the same identified record twice for one incident. A database uniqueness constraint guards against concurrent duplicate inserts. The same provider record can still appear in different incidents; missing identifiers are preserved rather than merged. Full nanosecond timestamp precision is included in the digest and retained in the evidence metadata. The collection limit still counts received records, including duplicates.

Migration `d52a0f18b721` follows the earlier GCP migration and must be applied before running this code against an existing Alembic-managed database. Existing records have no source digest; they are not retroactively deduplicated. The local ORM-created test database requires a separately assessed upgrade as described in `RUNNING.md`. Conflicting concurrent inserts fail the transaction rather than silently dropping evidence. Fallback identity when provider identifiers are missing, copy/download correlation, research import and validation against the reported experiment records are not yet implemented.

## Ninth increment: related-record groups

The incident detail computes read-only groups over stored GCP audit records. Records can be grouped by a complete provider operation ID and producer, or by an explicitly formatted client-supplied gcloud invocation ID. Groups are also scoped to the log's project and acting principal. Client invocation groups are medium confidence, limited to a 24-hour span and described as related records rather than completed operations; provider operation groups are high confidence for the shared identifier. Ambiguous or unsupported records remain ungrouped. The UI shows record outcomes and underlying records without deleting or modifying evidence. Group counts describe identifiers, not downloads, copies, confirmed key use or malicious activity.

This is an initial correlation layer: it does not infer copy source and destination pairs, unique downloads, command success or the reported five-copy ground truth. It depends on identifiers retained in the stored events, and shows all collected history rather than only the exposure window. The original experiment evidence remains unavailable for validation.

## Tenth increment: classification and coverage

The GCP taxonomy now treats object uploads, copies, snapshots, log-sink changes and budget updates as resource changes or data access rather than automatically asserting exfiltration or financial abuse. It recognizes the documented storage-layout method and selected service-scoped provider audit aliases for Secret Manager, Cloud KMS, Compute Engine and IAM. Unrecognized GCP methods remain visible and unclassified rather than receiving a guessed suffix-based category. When an exposure contains no successfully classified GCP events, the pipeline does not assign a low severity merely because the methods were unrecognized or attempts failed.

The incident timeline reports classified versus unclassified counts for stored history, separately from log-collection coverage. Previously classified database rows and saved reports are not rewritten automatically; refreshing replaces the collected history and is subject to provider access and retention. The implementation does not infer that an observed change was malicious, or establish what the experiment's original logs contain; actual evidence was unavailable for verification. Many provider methods and contextual classifications remain unmapped.

## Eleventh increment: bounded historical collection

Research → Historical GCP research starts a read-only background query for a selected BreachTrace project, a matching verified GCP wallet reader, a service-account principal, a scenario identifier and an explicit UTC range. A range may span at most 90 days; an attempt fails rather than truncating after 2,000 provider records read. The result uses the existing GCP collector, classifier and related-record grouping, and is stored in the background job as `research_forensic_evaluation`. It does not create an incident, claim a leak or add an unverified experiment run to comparison metrics. Access requires an administrator or security lead. The page displays the most recent query for the selected project and up to 100 records; the complete result can be retrieved by an authorized user at `GET /research/gcp-historical/{job_id}`.

To run a query, select the BreachTrace project, configure and verify its GCP wallet reader, then enter the reader's GCP project ID, the investigated service-account email, a scenario label such as `GCP-DATA-01`, and the historical start and end in UTC. The reader must be independent from the investigated identity. Collection still depends on backend ADC or the configured JSON reader, IAM permissions, enabled audit logging and retention. A successful empty response does not establish that no activity occurred.

This is not yet a ground-truth evaluator, downloadable research report, or complete historical experiment workflow. It has not been exercised against the original records or a live account; the high-level client also lacks a configured per-request timeout. The earlier database migrations are still required for the broader GCP changes.

## Twelfth increment: offline JSON import

The historical research form can also import a Cloud Logging JSON array without a GCP connection or wallet reader. Select the BreachTrace project and enter the expected GCP project, service-account principal, scenario label and UTC range, then choose the JSON file. Each record must be an audit entry for that project and principal inside the range. Malformed or out-of-scope records cause the entire import to fail. The importer accepts up to 5 MB and 2,000 records, retains nanosecond timestamps, and reuses the collector's evidence minimization, normalization, classifier and related-record grouping. Exact repeated provider records are counted once; conflicting copies of the same provider identity are rejected, and records without an insert ID are kept separately.

Only the minimized result and a SHA-256 digest of the uploaded bytes are retained in the existing research job; the original file and request/response bodies are not saved as job payloads. Identical files with the same project, principal, scenario and window reuse the existing result. The digest identifies bytes but does not prove that a file came from Google. Imported research evidence is distinct from live collection and incident evidence.

The actual Cloud Shell exports are not present in this workspace, so compatibility and the reported 6/15/25/5 counts have only been tested with synthetic fixtures, not verified against the user's files. Historical reports and copy/download correlation remain outstanding.

## Thirteenth increment: initial ground-truth comparison

After collecting or importing historical audit evidence, the Research page accepts a separate UTF-8 ground-truth CSV (up to 1 MB and 2,000 rows). The operator explicitly selects whether each row represents a command or an audit record and supplies the exact column names; no CSV schema is guessed.

- **Command rows:** select a non-empty command column. The comparison counts labelled rows but does not infer command-to-record matches, logical operation counts or collection completeness.
- **Audit-record rows:** select an insert-ID column and at least one expected-category or expected-outcome column. Expected outcomes are `success`, `failed`, `denied`, or `not_found`; categories are the existing BreachTrace category IDs or `unclassified`. Each CSV record ID must be unique. Labels are compared only when the insert ID identifies exactly one stored record in the selected evidence; missing and ambiguous IDs are reported separately. A generic expected `failed` agrees with denied or not-found outcomes. Accuracy and confusion counts apply only to uniquely matched, labelled records; they are not end-to-end precision, recall or completeness.

For example, an audit-record CSV with columns named `insert_id,expected_category,expected_outcome` can be used by mapping those three names in the form. This is an example schema, not a claim about the original files. The comparison records a digest, mapping and aggregate results in a separate research job; it does not store CSV row contents or modify the audit evidence. Repeating the same comparison against the same evidence returns the existing result. The uploaded file must be retained independently if a comparison needs to be reproduced.

The original CSV schemas and content are unavailable, so compatibility and the reported 20 commands have not been verified. Operator labels and file provenance are not independently established. Command matching, collection completeness, per-class precision/recall, operation correlation evaluation, timing metrics and research reports remain future work. Historical event age is never treated as detection latency.

## Local database migration and evidence availability

On 18 November 2026 the isolated local database at `127.0.0.1:55432/breachtrace_local_test` was backed up and migrated through Alembic to `d52a0f18b721`. Its recorded revision was behind several tables already created by the local bootstrap. The affected migrations now verify compatible existing tables, columns, constraints and indexes before proceeding, and fail on conflicts; they do not merely stamp the database. The path was rehearsed on a restored copy, including an incompatible-schema rollback test, and checked against a fresh temporary database. The original retained 32 incident rows and 579 forensic event rows during migration. The running backend was restarted against the updated schema.

The verified pre-migration backup is stored under gitignored `data/backups/` with owner-only file permissions. It contains database data and should be handled as sensitive. This migration status applies only to that local database, not other installations. The original Cloud Shell files were not found locally, and there is no connected Cloud Shell tool; the real-file checks remain outstanding.

## Incident collection client cleanup

The incident pipeline closes its Google Cloud Logging client after successful and failed collection, including validation failures. A cleanup error is logged by exception type without exposing provider response contents and does not replace the collection outcome. In the locally installed Google client, the underlying `list_log_entries` method supplies a 60-second default per-call timeout and retry deadline. BreachTrace does not override those defaults, and a multi-page collection has no overall deadline. SDK defaults may differ with dependency versions.

## Remaining stages

Complete structured detection, keyed secret fingerprinting and API-key resolution, historical collection controls, complete status/attribution normalization, copy/download correlation, controlled historical import/evaluation, and integration validation against the actual files remain to be implemented. No claim is made that the full GCP plan is complete.
