# BreachTrace research dossier

This file is a detailed source document for planning a research paper about BreachTrace. It records the product as implemented, the work present on the research branch, relevant research context, candidate research questions, evidence available today, and work still needed before making scientific claims. It is not a finished paper and its proposed contributions must not be presented as established results.

**Implementation snapshot:** branch `ese1`, commit `34c985f` (`Improve credential forensics and landing page`), inspected 17 November 2026. The branch is pushed to `origin/ese1`. A comparison from the research seed commit `5e86a47` to this snapshot includes 129 changed files, 6,336 insertions and 660 deletions. That is a code-change summary, not a research result.

## 1. Research framing

### 1.1 The problem

Credential scanners answer a narrow question: does repository content resemble a credential? An incident responder still needs to establish what was exposed, when exposure plausibly began, which provider records can be queried, what those records show, whether they can be linked to the exposed credential, and what can safely be concluded when records are missing.

BreachTrace is a prototype that connects repository-level candidate detection to provider-specific collection and evidence-aware incident reporting. Its research value is not that secret detection is solved, that it can prove every event was caused by a leaked key, or that it automatically establishes the full life of a credential. The researchable claim is narrower: **a single, explicit workflow can connect a detected repository exposure to authorized provider records, normalize those records, distinguish pre-exposure context from post-exposure activity, and expose the limits of attribution to an investigator.** Whether this workflow is more accurate, useful, or complete than existing practice remains to be evaluated.

### 1.2 Novelty must be established, not asserted

Avoid writing that existing research or products “stop at detection,” that detection is “solved,” or that no other system performs post-exposure correlation. Prior work has measured leaked credentials and their removal over time, studied developer remediation experiences, compared scanner quality, and experimentally observed attacker operations on exposed cloud credentials. For example, *How Bad Can It Git?* measured secret discovery and removal at GitHub scale; *Pushed by Accident* studied developer experiences and remediation needs; and Unit 42’s CloudKeys report describes a controlled exposed-AWS-key experiment with activity observed in CloudTrail. These works do not by themselves establish that an integrated, evidence-limited, multi-provider response workflow has been evaluated, but they make an absolute “nothing else does this” claim unsafe. See [Meli et al., NDSS 2019](https://doi.org/10.14722/ndss.2019.23418), [Krause et al., USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-krause.pdf), and [Unit 42, CloudKeys in the Air](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/).

The defensible contribution must be defined after a current related-work review. A plausible contribution is a **cross-provider implementation and controlled evaluation of the evidence path from a code exposure signal to provider audit records**, including source-specific attribution ceilings, temporal semantics, failure handling, and investigator-facing uncertainty. It is an implementation-and-evaluation contribution, not a claim that BreachTrace invented secret scanning or cloud forensics.

Secret detection remains an active measurement problem. A comparison of nine tools found trade-offs between precision and recall and attributed errors to generic patterns and incomplete rulesets. This is a reason to include a validated detector baseline in the paper rather than treating detection as solved. [Basak et al., ACM/IEEE ESEM 2023](https://doi.org/10.1109/ESEM56168.2023.10304853).

### 1.3 Three research directions

| Direction | Research focus | Readiness in this branch | Suggested role |
|---|---|---|---|
| 1. From leak to impact | Controlled evaluation of evidence collection, temporal correlation, attribution, and triage across provider audit sources | The system and several test harnesses exist; a clean, post-exposure, ground-truthed cross-provider evaluation is not yet evidenced | Best candidate for the main paper, after fixing the experimental chronology and running an authorized study |
| 2. Measuring public-repository exposure | Passive prevalence and remediation-window measurement | Current snapshot scanner and stress fixtures exist; there is no large-scale public corpus study or independently labelled dataset in this branch | A separate measurement paper with careful sampling, consent/ethics review, and no credential use |
| 3. LLM-assisted forensic narratives | Faithfulness, omissions, privacy, and analyst utility of optional generated prose | A deterministic report path, optional model writers, validation, retrieval, and a tiny synthetic pilot exist | A secondary evaluation section in Paper 1; weak as a standalone claim without a larger controlled human/model study |

## 2. What BreachTrace implements

### 2.1 Inputs and incident creation

BreachTrace has two GitHub-related entry points with different semantics:

1. **Current repository snapshot.** An operator submits a GitHub repository URL. The backend resolves the default branch to a commit, downloads a bounded archive, and scans eligible text files without executing repository code. This produces a snapshot finding in Connect. An operator may add it to Monitor as a detection-only record. The snapshot does not infer the first exposure time, scan all Git history, or start provider forensics.
2. **Future push monitoring.** GitHub sends a push delivery to `/webhook/github`. The route remains unauthenticated by JWT; the delivery is verified using the configured HMAC signature. The backend scans added lines from commits in the payload and may create an incident for a qualifying match. Registering a webhook does not backfill old commits.

In the push workflow, the commit timestamp is recorded as the estimated `exposure_start`. It is not verified as the time the key first became accessible to an adversary. It does not reconstruct branch ancestry, public/private visibility transitions, forks, clones, cached copies, or earlier occurrences in history. A private push can trigger an incident even though it does not establish public exposure.

Findings retain credential family, source path and line, confidence/match metadata, a masked hint and a fingerprint. The full detected value is not intended to be a reusable incident secret. Static recovery supports bounded encodings and literal-only source constructions; repository code is not executed. Candidate recognition is not provider-side validity checking.

The AI credential catalog registers 49 candidate families. Nine have distinctive standalone prefix rules; others need a named configuration field, SDK/endpoint context or structured JSON provider context. Static recovery covers Base64/Base64URL and one additional encoding layer, hexadecimal, Unicode/hex escapes, URL percent encoding, HTML entities, zero-width characters, string concatenation, literal-only joins, reversed literals and explicitly marked ROT13. Recovery is deliberately bounded (two layers, 4,096 transforms, 1 MiB aggregate decoded text per file, bounded literals/config depth); a budget exhaustion is a diagnostic and can make scan coverage incomplete. No runtime evaluation, cross-file assembly, arbitrary data-flow, encryption breaking or vendor validation is performed. The detailed family list and rules are in [ai-detection.md](../ai-detection.md).

Current repository-snapshot defaults documented for this branch are 10 MiB per file, 1 GiB of text, 200,000 files, 10,000 findings, a 2 GiB compressed archive, a five-minute archive download cap and a ten-minute scan timeout. The scanner skips Git history, binaries, symlinks/special files, submodules and excluded dependency/build paths. These are current-code defaults to confirm at the frozen experiment commit, not guaranteed completeness bounds for all repositories.

### 2.2 Exposure time and collection time are different

The live workflow records a commit-derived start estimate. Current provider collection requests up to 30 days of history ending at collection time, subject to provider retention, reader permission, API caps, pagination, and configured logs. Events before the commit-derived start can be retained and shown as historical context. Severity, impact calculations and the incident report use events at or after that estimated start.

In normal live incidents, `exposure_end` is not automatically established by polling a leaked key until rotation. The webhook has a short experimental revocation monitor for explicitly configured experiment identities, and the codebase also contains a separate legacy monitoring utility. These special paths do not establish automatic lifecycle tracking for ordinary incidents, and recorded closure does not include independent provider-side provenance. Therefore, the current system cannot reliably compute the full interval from first exposure to confirmed revocation.

The current interval is best named a **collection interval** or **analysis interval**. It is not equivalent to the credential’s actual exposure window. It may include records from before the detected commit, and it may not extend to rotation. This distinction is central to the proposed temporal research.

The implementation decision and provider-specific evidence limits are recorded in [exposure and attribution scope](../exposure-attribution.md). In particular, future work may add provider-confirmed revocation observations with provenance, or credential-specific sign-in and audit records when a provider supplies a reliable key identifier. Until then, closure is not claimed as verified and app/account-level activity is not labelled as key-level use.

### 2.3 Forensic pipeline

For a supported and sufficiently identified credential, the backend routes to a provider collector, normalizes returned records, stores event rows, classifies operations, computes deterministic severity and impact, creates a report, and indexes evidence for search. A manual refresh reruns collection using configured reader access. Project incidents use a verified reader from their project's encrypted wallet; legacy incidents without a project use backend environment configuration. This paragraph records the later wallet integration and supersedes the implementation snapshot's wallet limitation.

The common event representation records available fields such as timestamp, provider, operation, principal/caller, resource, source address, success/error and sanitized evidence metadata. Provider schemas are not equivalent. Normalization makes them queryable in a shared UI, but it does not make the underlying logs equally complete or equally attributable.

The event categories include reconnaissance, data access, exfiltration, resource abuse, privilege escalation, financial abuse, communication abuse and code compromise. Deterministic rules and severity weights map provider actions into these categories. Severity is an analyst-prioritization heuristic, not a calibrated probability of compromise. Financial lines may use a provider-reported amount or an estimate; they are not invoices and do not prove the exposed credential caused the transaction.

### 2.4 Evidence and attribution vocabulary

Use these distinctions consistently in a paper and product claims:

| Term | Meaning |
|---|---|
| Candidate | A detector matched source content to a credential family or contextual pattern |
| Provider activity | A provider returned a record in the requested interval |
| Identity-correlated activity | The record matched an account, application, principal, or other identity associated with the finding |
| Credential-level attribution | Provider evidence identifies the exact key/token/secret that made the request |
| Causal attribution | Evidence supports the conclusion that this exposed credential caused this action |
| No returned records | The collector returned no matching records; this is not proof the credential was unused |

These are not interchangeable. A log row in the same account and time interval is weaker evidence than a row containing the exact key identifier. Provider APIs may omit read operations, data-plane access, denied calls, request identities, source IPs, or records outside retention. An incident marked complete means its processing finished; it does not prove malicious use, complete logging, rotation, or remediation.

The Tier 1 label means BreachTrace has an implemented collection path it can attempt with enough identity and access information. Tier 2 means detection and investigation guidance without that live collection path. Tier 1 does not mean a finding is confirmed valid or that provider evidence identifies a particular leaked key.

### 2.5 Provider coverage and attribution ceilings

| Provider | Current source | What identity can be correlated | Main attribution or visibility limit |
|---|---|---|---|
| AWS | CloudTrail | Provider identity fields, when present in returned records | Log configuration, scope, retention and identity fields determine whether activity can be linked to a specific access key; an empty result is inconclusive |
| Google Cloud / Firebase | Cloud Audit Logs | Service-account identity where available | Depends on audit-log type, project, permissions, retention and whether the operation is logged |
| Azure | Azure Monitor Activity Log | Exact app ID in identity claims, or exact caller; an operator may associate a client ID with a detected client secret | Primarily control-plane activity. One app ID may correspond to multiple client secrets; the current collector does not isolate a leaked client secret by credential key ID. Same-app incidents can therefore show the same app-level records |
| Stripe Events API | Account events, requested through the exposed key during initial collection when usable, or a configured same-account/same-mode reader on refresh | Account state changes and sometimes a request ID | Events are account-wide and do not say which key made the request. GET/read-only requests are not represented as Events. Ordinary account events are not evidence that a leaked key caused them |
| Stripe CLI request stream | Optional, separately supervised sandbox stream for new request metadata | Request ID, method, reduced path, status and timestamp | Does not backfill, does not stream live-mode request logs, and does not identify which API key made the request. It is supplementary to normal backend Events collection |
| Twilio | Account-scoped Messages, Calls and Monitor resources | Owning Account SID and account-level resource activity | Not per-API-key attribution; message bodies are not retained; logs and resource types depend on the account reader and provider history |
| Most other SaaS, database and AI key families | Detection/report workflow | Repository source provenance | No live collector in the present implementation |

Azure needs a particularly careful treatment. Activity Log calls are filtered by time and then matched locally to the application ID from identity claims or an exact caller value. This corrected an earlier assumption that the caller field would always equal the application ID. It still yields application-level attribution, not a unique secret-key attribution. Microsoft Graph sign-in records can expose a `servicePrincipalCredentialKeyId` in supported data and may help establish which credential was used at token issuance, but that is a distinct API and permission path. The configured reader previously received HTTP 403 for the sign-in query because required Graph permission was unavailable. The feature is not implemented. See [Microsoft Graph sign-in resource](https://learn.microsoft.com/en-us/graph/api/resources/signIn?view=graph-rest-beta) and [list sign-ins permissions](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta).

Stripe has two separate paths. The normal collector queries Events through the backend and returns state-change evidence over the available window. The optional CLI stream is a different process that can capture new sandbox request metadata, including some GETs, only while connected. Neither path labels a request with the exact exposed key. In particular, the fact that an API key can read account events does not mean each returned event was made using that key.

Twilio requires account context: an `SK` SID identifies an API key, while an `AC` SID identifies the owning account. An `SK` alone does not enable collection. The resulting messages/calls/monitor records describe account activity; they do not prove which API key performed each action.

## 3. Actual user journey and branch implementation

### 3.1 User journey in the current product

1. An administrator creates the initial organization and user, signs in, creates or selects a project, and assigns project members/roles.
2. The administrator connects a GitHub repository and registers a push webhook. The webhook secret is project-specific and encrypted at rest. GitHub’s delivery is authenticated through HMAC on the unauthenticated webhook route, not through the user’s JWT.
3. A future signed push with a matching credential in added content creates an incident. A manual repository scan is a separate snapshot workflow; a user can explicitly add a finding as a detection-only Monitor record.
4. Monitor shows incidents after the webhook pipeline sees qualifying content. Incident detail shows the masked candidate, estimated commit exposure time, collection status, report, timeline and available impact fields. Pre-exposure records are labelled as context; post-exposure evidence drives severity and impact.
5. Administrators/security leads may refresh supported logs, associate an Azure application ID or Twilio account SID where needed, assign an incident, dismiss it with an audited action, and export a PDF. Association is an operator assertion and is not provider proof of key ownership.
6. Project email/Slack destinations can receive best-effort incident notices. Organization/incident audit views record selected investigation and administration actions. Notification delivery has no durable retry queue in this branch.
7. Search retrieves stored incident/report/knowledge/event evidence. A grounded model answer is optional. A deterministic report is the fallback and does not require an LLM.

The user journey matters for the paper because UI wording can change the evidence claim. For instance, a snapshot finding is not an incident with an exposure timestamp; a timeline row is not necessarily attributable to a leaked key; and a completed incident is not a confirmed rotation.

### 3.2 Material implementation work on branch `ese1`

The following list summarizes the work accumulated from the research seed commit through `34c985f`. These are implementation facts, not quality or impact results.

| Workstream | Implemented in this branch | Research relevance and remaining boundary |
|---|---|---|
| Account and project foundation | Initial setup/authentication, organization and project records, memberships/roles, project-aware incident access | Allows role-separated investigations; deployment hardening and full tenant isolation remain incomplete |
| Webhook and incident routing | Project-specific repository webhook configuration, encrypted webhook secrets, repository-to-project routing, incident authorization | Enables a more realistic team workflow. Webhook stays unauthenticated by JWT and verifies HMAC; do not add blanket JWT middleware to that route |
| Credential wallet | Encrypted per-project provider connection metadata, provider verification flows, protected secret display behavior | Verification proves limited reader access, not exposed-key ownership. Since the documented snapshot, collection has been connected to verified project readers |
| Incident response operations | Assignment, dismissal, refresh/access audit records, PDF report, organization and incident audit views | Provides traceability for a human workflow; does not make the product a durable enterprise case-management system |
| Notifications | Project SMTP and Slack destinations and threshold-based best-effort notices | Useful for operational routing; no retry queue or durable delivery receipts |
| Azure collection | Time-bounded Activity Log paging with exact app/caller matching and local identity-claim filtering; Azure key-pattern context and taxonomy improvements | Improves app-level collection and classification. Does not establish per-client-secret attribution or comprehensive data-plane coverage |
| Azure research scenarios | Nine registered scenario types: reconnaissance, data, exfiltration, abuse, privilege escalation, code, communication, financial and bulk activity; cleanup/revocation hooks and event expectation diffing | Provides experiment scaffolding, not proof that nine live scenarios ran or succeeded. The current action-before-leak ordering makes observed calls pre-exposure context; revise before using it to measure post-leak exploitation |
| Stripe forensics | Normal backend Events collection, 30-day historical query and mode/account-aware reader refresh; sanitized event fields; optional request-log metadata ingest/worker | Demonstrates different observability for state-changing events vs request logs. Events miss GET/read-only traffic; request stream is optional, sandbox-only and not key-attributed |
| Twilio forensics | Account-scoped message/call/monitor collection, API-key or Auth Token reader support, bounds and safe event mapping | Adds SaaS evidence collection but remains account-wide; no exact `SK` per-request key attribution, and message content is excluded |
| Temporal analysis | 30-day historical collection context, normalization of timestamps to UTC, explicit pre-exposure labels, and post-exposure filtering for scoring/impact/report calculations | Makes temporal semantics visible, but current start time is a commit estimate and end/rotation is not automatically observed |
| Detection and repository processing | Expanded credential patterns/context, Azure scenario secret context, bounded snapshot scanning, result coverage information and static obfuscation support | Supports the detector pipeline. Does not make snapshot scanning a full-history scanner or provide independent accuracy results |
| Reports and search | Deterministic reports, optional external/local model prose, report validation, retrieval-grounded answers and citations to stored evidence | Keeps deterministic evidence and model prose separate; generated output still needs a rigorous faithfulness/user evaluation |
| Research tooling | Azure scenario runner, experiment recording, repository stress harness, report-model benchmark/evaluation tooling, synthetic demo support | Makes reproducible work more feasible, but the current fixtures and small pilots are not a benchmark of real incident performance |
| Landing/UI | Separate BreachTrace landing page and investigation UI refinements | Product presentation only. No user study or usability result is established by the visual implementation |

Other useful source maps are in [app-context.md](../app-context.md), [deployment notes](../DEPLOYMENT.md), [credential-wallet.md](../credential-wallet.md), [project-incident-routing.md](../project-incident-routing.md), [incident-actions.md](../incident-actions.md), [notifications.md](../notifications.md) and [stripe-request-stream.md](../stripe-request-stream.md).

### 3.3 Research-relevant code map

| Concern | Implementation location |
|---|---|
| GitHub snapshot and push input | [repository_snapshot.py](../../backend/repository_snapshot.py), detector modules under [backend/detector](../../backend/detector), [webhook.py](../../backend/routers/webhook.py) |
| Provider dispatch and processing | [pipeline.py](../../backend/pipeline.py), collectors under [backend/collectors](../../backend/collectors) |
| Azure identity matching | [azure.py](../../backend/collectors/azure.py), Azure taxonomy and scenarios under [backend/research/scenarios/azure](../../backend/research/scenarios/azure) |
| Stripe account events and request metadata | [stripe.py](../../backend/collectors/stripe.py), [stripe_request_logs.py](../../scripts/stripe_request_logs.py), [stripe-request-stream.md](../stripe-request-stream.md) |
| Twilio collection | [twilio.py](../../backend/collectors/twilio.py), [taxonomy_twilio.py](../../backend/classifier/taxonomy_twilio.py) |
| Temporal classification and severity | [time_window.py](../../backend/normalizer/time_window.py), [rules.py](../../backend/classifier/rules.py), [severity.py](../../backend/scorer/severity.py) |
| Incident display and actions | [IncidentDetail.tsx](../../client/src/pages/IncidentDetail.tsx), [incidents.py](../../backend/routers/incidents.py) |
| User roles, projects, audit and wallet | [auth.py](../../backend/routers/auth.py), [org.py](../../backend/routers/org.py), [projects.py](../../backend/routers/projects.py), [wallet.py](../../backend/routers/wallet.py), [models.py](../../backend/db/models.py) |
| Report validation and research harness | [validate.py](../../backend/reporter/validate.py), [research directory](../../backend/research) |

## 4. Paper 1: From Leak to Impact

### 4.1 Candidate title and claim

**Candidate title:** *From Leak to Impact: Evaluating Evidence Correlation for Exposed API Credentials Across Cloud and SaaS Audit Sources*

This is the strongest direction because it evaluates the transition from a repository signal to provider evidence rather than proposing another scanner. The key research object is not a binary “compromised/not compromised” outcome. It is the quality and scope of the evidence BreachTrace can collect and attribute, given provider-specific logging behavior and the time at which the exposure was detected.

The paper can make a contribution only if it demonstrates the collection pipeline under controlled conditions and reports blind spots. Code presence alone does not show that the system can answer its research questions. At present, this branch is a prototype plus evaluation scaffolding, not a completed evaluation of post-exposure forensic attribution.

### 4.2 Background and gap to test

Prior secret-leakage work supplies three relevant baselines:

- Large-scale repository studies establish prevalence, time-to-discovery/removal and the difficulty of mining secrets accurately. They primarily measure repository exposure and remediation, not a unified workflow that maps the same controlled exposure to post-exposure audit evidence. See [Meli et al.](https://doi.org/10.14722/ndss.2019.23418).
- Developer-focused work finds that leak risk and remediation are hard to assess and documents what developers need after a leak. This motivates a usable evidence summary but does not validate BreachTrace’s scoring. See [Krause et al.](https://www.usenix.org/system/files/usenixsecurity23-krause.pdf).
- Controlled cloud-credential studies have observed attacker operations in a test environment through CloudTrail. These are important prior examples of post-exposure activity measurement and prevent an absolute novelty claim. They are not the same as measuring a reusable, cross-provider correlation pipeline and its false attribution/coverage limits. See [Unit 42 CloudKeys](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/).

The research gap to validate is therefore **integration and comparative evaluation across provider log contracts**, especially how much evidence is available, how quickly it arrives, which identity level it supports, and how a downstream analyst should interpret missing or ambiguous records. A literature review should search secret leakage, exposed credential exploitation, cloud auditability, credential attribution, incident response automation and SaaS audit APIs before asserting the gap.

### 4.3 Research questions

| RQ | Question | Current implementation status |
|---|---|---|
| RQ1: Temporal validity | How accurately can BreachTrace estimate the start of an exposure and its end at confirmed revocation, including Git history, branch/fork and visibility effects? | Only the triggering push commit timestamp is used as an estimated start. Snapshot scan gives no exposure time. Fork/public-visibility history and automatic rotation/end-time measurement are not implemented in the live workflow. This question is future work, not an existing result. |
| RQ2: Audit coverage | For controlled credential use after a known exposure, which provider events are available through each supported audit API, at what delay, and for which action classes? | Collectors exist for AWS, GCP, Azure, Stripe Events and Twilio, but there is not yet a clean, executed, common-ground-truth comparison across all five. Azure Activity Log is control-plane weighted, Stripe Events omit read-only calls, and Twilio is account-scoped. |
| RQ3: Attribution | At what level can each returned event be attributed: account, application/principal, or exact exposed credential? | The UI and collector document some limits, but no full attribution benchmark exists. Azure client-secret IDs are not distinguished; Stripe Events and CLI stream do not identify the key; Twilio account resources are not per-key. |
| RQ4: Triage quality | Do deterministic categories and severity scores agree with blinded expert/analyst judgments, and do they reduce triage time without increasing dangerous false reassurance? | The rules and severity scorer exist. There is no blinded analyst study, calibrated decision threshold, or validated severity accuracy measure in this branch. |
| RQ5: Operational cost | What are collection completion time, API calls/pages, permission failures, rate limits, and resource cost by provider and event volume? | Limits, retry logic and sanitized collector errors exist. A unified performance dataset and cost study remain to be run. |

### 4.4 Proposed hypotheses, stated as testable expectations

Do not put fixed numerical thresholds in the abstract before a pilot establishes feasibility. Candidate hypotheses are:

- **H1:** Provider event observability differs systematically by provider and action class; write/control-plane actions are captured more often than read-only or data-plane actions in some supported APIs.
- **H2:** Same-account or same-principal correlation yields more returned context than key-level attribution, but can increase benign-event contamination.
- **H3:** Explicitly separating pre-exposure context from post-exposure events reduces false incident severity compared with scoring all records in the collection interval.
- **H4:** A report that labels evidence level and collection blind spots leads analysts to make fewer unsupported “unused” or “confirmed compromised” judgments than an unlabeled timeline.

H3 and H4 require direct baselines and human evaluation. They are not consequences of the implementation itself.

### 4.5 Recommended controlled evaluation protocol

1. **Environment.** Create isolated, owner-controlled test accounts/projects and disposable test identities for AWS, Google Cloud, Azure, Stripe sandbox and Twilio test resources. Use only synthetic data and a budget limit. Configure the relevant audit sources before the experiment and retain their configuration metadata.
2. **Credential lifecycle ground truth.** Record issuance time, credential identifier/key ID if provider exposes one, the exact controlled exposure marker, permitted actions, action timestamps, response outcomes, revocation time and confirmation method. Do not publish active provider credentials to an uncontrolled public repository. A private test repository or an isolated simulated webhook can test the app path; a separate experiment is needed to measure real public discovery.
3. **Post-exposure ordering.** First trigger a signed test push containing the controlled test credential so BreachTrace establishes the exposure timestamp. Then issue a preregistered, low-impact API action sequence using only that test credential. Wait for provider log ingestion using a documented bound, refresh the incident, and compare returned rows to independently saved request/action ground truth. Do not use historical calls before the exposure marker as evidence of post-exposure exploitation.
4. **Controls.** Include (a) normal owner activity under a different credential/principal, (b) activity before exposure, (c) no-action exposures, (d) allowed and denied calls, (e) read-only calls, (f) events with delayed ingestion, and (g) revoked/invalid credential cases. Clearly identify tests where the audit API cannot observe an action.
5. **Repetitions and order.** Repeat each provider/action condition across fresh disposable credentials and randomized run order. Keep provider account, region, API version, log configuration, test mode, permissions, timestamps and software commit fixed and archived. Separate setup/cleanup events from actions under test.
6. **Attribution labels.** Maintain ground truth for key ID, service principal/app ID, account ID and request ID where available. Evaluate exact-key, principal-level and account-only matching separately; never count them all as equivalent true positives.
7. **Cleanup.** Revoke test credentials, delete scratch resources, verify cleanup, and save sanitized evidence manifests. A failed cleanup must stop the run and be recorded.

The branch already has nine Azure scenario definitions and a framework that creates/uses an experiment identity, polls for audit records, submits a simulated diff, compares expected actions/categories/severity and attempts cleanup/revocation. The scenario ordering needs correction before the framework can evaluate post-exposure exploitation: current code performs actions first, waits for logs, and only then submits the simulated exposure. Those actions are pre-exposure relative to the recorded timestamp and should be historical context. Existing scenario code and taxonomy tests prove that scenarios are registered and that expected action names map to taxonomy entries; they do not prove nine live experiments were run or that post-exposure activity was captured.

There is also a stale lookback comment in the scenario framework describing a 120-minute pre-exposure collection window. The current pipeline requests 30 days of history before collection time. Reconcile code, comments, scenario assumptions and experiment metadata before freezing any run; otherwise a reader cannot reproduce which interval was actually queried.

### 4.6 Measures and analysis plan

Report results by provider, action type, permission profile, credential attribution level and log delay. Recommended measures:

- **Event capture recall:** ground-truth actions returned by the collector divided by ground-truth actions expected to be logged under the configured provider policy. Report “not expected to be logged” separately from missing.
- **Event mapping accuracy:** exact action extraction, timestamp error, principal/key identifier match, resource mapping, success/error mapping and taxonomy label compared with hand-labelled ground truth.
- **Attribution precision/recall:** at each identity level, with ambiguity and shared-account contamination reported separately.
- **Pre/post temporal correctness:** whether the system puts controlled pre-exposure events into context and excludes them from post-exposure severity/impact calculations; report boundary error in seconds.
- **Collection availability and latency:** successful collections, errors by sanitized class, paging, API request count and elapsed time from action to visible event.
- **Triage quality:** severity agreement (weighted kappa or an ordinal measure), false reassurance, overstatement of causality, and analyst time against a baseline report/timeline.
- **Robustness:** behavior on missing IDs, stale credentials, permission denial, retention gaps, API truncation, late-arriving events, clock skew and duplicate events.

Define denominator and provider audit expectation before each run. Some providers do not promise to record all read requests or API calls in the endpoint used by this prototype. An event absent from the provider endpoint is not a detector false negative if the provider did not log that event, but it is relevant to end-to-end observability and should be included in coverage limits.

### 4.7 What Paper 1 can claim today

Supported by repository evidence: there is a working prototype with a GitHub push path, timestamped incident records, five provider collector families, a normalized event schema, provider-specific taxonomies, post-exposure scoring, visible historical context, deterministic report generation, and explicit collection states/limitations.

Not supported yet: superior accuracy versus commercial tools, reliable full exposure-window calculation, key-level attribution across providers, complete read-only request capture, validated severity prediction, measured analyst time savings, or confirmed capture rates across all platforms. The paper should frame these as evaluation targets until the proposed study is complete.

## 5. Paper 2: Public-repository exposure measurement

### 5.1 Candidate title and scope

**Candidate title:** *Measuring Credential Exposure and Remediation in Public Source Repositories: A Passive, Privacy-Preserving Study*

This direction asks prevalence and lifecycle questions, not whether a found key can be used. It is not currently implemented as a large-scale measurement study. The existing snapshot scanner processes a repository the user submits and does not scan Git history; public-repository stress runs are a few unlabelled engineering observations, not a corpus.

### 5.2 Context from prior work

Meli et al. already performed a longitudinal GitHub study at a much larger scale, including time-to-discovery/removal and candidate validation. Basak et al. compare scanner reporting quality. The branch cannot claim a new prevalence result from scanning VS Code and FastAPI once. A defensible new study needs a distinct question or dataset, a carefully evaluated detector, a sampling plan, current platform context, and a reproducible protocol. [Meli et al.](https://doi.org/10.14722/ndss.2019.23418); [Basak et al.](https://doi.org/10.1109/ESEM56168.2023.10304853).

### 5.3 Possible research questions

- What candidate credential families and file contexts occur in a defined, sampled corpus of public repositories over a preregistered interval?
- How long do candidate strings remain in the visible default branch after first observation, and how often do deleted items persist in reachable history or forks?
- How do observed removal intervals differ by repository type, file context, provider family and available public metadata?
- How often does a high-confidence candidate pass independent human review, and what are the dominant false-positive/false-negative cases?

Do not infer that deletion equals credential revocation. Do not infer that a credential was valid or abused. Removal time from a repository is a VCS visibility measure, not rotation time.

### 5.4 Safe study design

- Use only public repository metadata and content whose collection is permitted by platform terms and institutional policy. Obtain advisor/institutional ethics review before collection and responsible-disclosure guidance before contacting owners.
- Do not authenticate with candidates, send them to provider validation APIs, enumerate associated accounts, fetch private data, or attempt to attribute provider activity. “Already revoked” must be evidenced by an authorized owner or public remediation record; do not independently test a candidate to decide.
- Minimize sensitive data. Store candidate hashes with a study-specific keyed HMAC, never raw secrets; retain only masked samples needed for label review; segregate and restrict any exceptional raw evidence under institutional procedures; delete it on a predeclared schedule.
- Deduplicate reposts and forks without publishing a search index that makes credentials easier to find. Avoid including repository names/paths in public artifacts if that would re-expose a live credential. Use delayed aggregate reporting, responsible disclosure and a documented takedown/response process.
- Build independent labels using at least two reviewers on a protected, sampled subset. Record disagreement, adjudication, confidence and family-specific label criteria. Do not treat scanner agreement as ground truth.
- Publish sampling frame, collection time, rate limits, exclusions, deduplication, model/rule version, ethics decisions and privacy-preserving aggregate output. Explain the survivorship bias of the chosen source and censoring for keys not yet removed.

### 5.5 What this branch contributes, and what it does not

The branch supplies a bounded current-snapshot scanner, pattern registry, static obfuscation recovery, masked findings, scan completeness metadata, and a repository stress harness. It excludes `.git` history, binaries, symlinks, submodules and configured dependency/build paths. It can process a submitted repository’s current text files but does not provide the longitudinal GitHub crawler, history/fork reconstruction, independently labelled corpus, ethics protocol, or active-key validity data needed for a prevalence or survival paper.

The public scans documented in [repository-stress.md](repository-stress.md) were engineering stress tests, not an epidemiological sample. They used unlabelled repositories and therefore cannot yield precision, recall, or prevalence estimates. The synthetic Groq-shaped probe validates one controlled match path only.

## 6. Paper 3: LLM-assisted forensic narratives

### 6.1 Candidate title and scope

**Candidate title:** *Evidence-Constrained Language Models for Privacy-Aware Credential Incident Reporting*

The product can generate optional report prose and grounded search answers, but deterministic facts, severity and remediation calculations are produced independently. This angle asks whether models help communicate provider evidence without inventing events, hiding uncertainty, or leaking sensitive information. It should not be framed as a novel general-purpose “LLM for security log analysis” system.

### 6.2 Related research and implications

Security incident summarization has already been evaluated with practicing analysts. The SOUPS 2025 study *Integrating Large Language Models into Security Incident Response* reports that collaboration and analyst review are more appropriate than autonomous incident response in the near term. [Kramer et al., SOUPS 2025](https://www.usenix.org/system/files/soups2025-kramer.pdf).

The 2026 AuditBench work evaluates models on labelled audit-log investigation tasks and finds mixed performance and false-positive tendencies, underscoring the need for task-specific evaluation. [Anand et al., AuditBench](https://arxiv.org/abs/2606.10281). The 2026 USENIX Security LogInject work demonstrates passive prompt-injection risk when untrusted log fields are fed to LLM analysis. This is directly relevant to audit events whose resource names, messages or metadata may be attacker-controlled. [Karanjai et al., USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/karanjai).

Therefore, a useful BreachTrace study should assess evidence faithfulness, omission, uncertainty wording, privacy, and analyst usefulness. A fluent narrative or a successful JSON parse is not a safety or correctness result.

### 6.3 What the branch implements

- Deterministic reports are available without an LLM.
- Optional hosted providers and local Ollama/GGUF paths can generate report prose.
- The generated prose is derived from a structured fact sheet. Validation checks credential-shaped material, identifiers, amounts/counts, provider vocabulary, claims unsupported by the facts, empty-timeline “unused” claims, and length.
- Search retrieves stored evidence and can optionally request a grounded answer with citations to retrieved passages. Citations point to retrieved text; they do not independently prove a generated conclusion.
- Model outputs cannot set deterministic severity or financial calculations.
- Research scripts support model benchmarking, report evaluation and a proposed training/distillation path. A validated BreachTrace model is not bundled.

These controls reduce some classes of error but do not eliminate semantic hallucination, omissions, prompt injection in log data, or unsafe recommendations. The code validator documents a residual gap: some ordinary-looking invented resource names cannot be detected by shape matching.

### 6.4 Existing pilot results

The committed [local model benchmark pilot](model-benchmark-pilot.md) is dated 3 November 2026 and contains four synthetic incident fact sheets per writer. The machine was Apple Silicon with 16 GB RAM; Ollama used Metal. It is a small engineering pilot, not a statistically reliable model ranking.

| Writer | Cases | Valid JSON | Validator pass | Mean fact coverage | Median latency | Observed slowest case (reported as p95 in pilot) |
|---|---:|---:|---:|---:|---:|---:|
| Deterministic template | 4 | 100% | 100% | 100.0% | 0.000 s | 0.000 s |
| llama3.2:latest | 4 | 100% | 75% | 62.5% | 18.634 s | 29.002 s |
| qwen2.5vl:3b | 4 | 100% | 75% | 31.2% | 21.129 s | 22.182 s |

The pilot explicitly says there was no blind human review, four cases do not support a reliable percentile or model ranking, a validator pass is not factual accuracy, and allocation samples are not peak-RAM measurements. The deterministic template performed best on this small fixture; do not generalize beyond it.

The retrieval fixture reported keyword recall@1 = 0.860, recall@3 = 0.930 and recall@5 = 0.953. This is a passage-retrieval fixture score. It is not answer accuracy, incident reconstruction accuracy, or proof that a generated statement is correct. Use [model-benchmark-pilot.md](model-benchmark-pilot.md) and its raw JSON as the source of record; do not mix older numbers copied into previous drafts.

### 6.5 Recommended evaluation

- Construct a larger, stratified, synthetic and consented case set with ground-truth event facts, ambiguous cases, empty logs, conflicting timestamps, noisy benign events, irrelevant retrieved passages and adversarial log text.
- Compare deterministic template, each local model, each hosted model, and human-written reference reports. Freeze prompts, model versions, decoding settings and validator versions.
- Randomize report order and blind human raters to system/model. Have at least two security practitioners score event correctness, unsupported claims, omissions, uncertainty calibration, actionability, readability and time-to-triage. Measure inter-rater agreement and adjudicate disagreements.
- Measure privacy separately: what fields leave the machine in hosted mode, what remains local, logging/retention behavior, and whether secret values are masked before model calls. Do not put real customer audit data into an external model for research without explicit authorization and review.
- Inject adversarial instructions into event fields, resource labels and retrieved passages. Test concealment, severity inflation, fabricated activity, data exfiltration and output-hijacking. Validate defense-in-depth and human review.
- Keep LLM output advisory. The model must not approve key validity, determine final severity, invoke destructive response, or assert that no compromise occurred solely because no events were returned.

This topic is stronger as a carefully bounded component of Paper 1 than as a standalone paper unless the team conducts a substantial model comparison and user study.

## 7. Existing engineering and research evidence

### 7.1 Repository scan observations

The documented 3 November 2026 stress observations on Darwin arm64 include:

| Input | Text files | Text bytes / reported MiB | Time | Findings | Interpretation |
|---|---:|---:|---:|---:|---|
| microsoft/vscode snapshot | 20,392 | 269,445,059 bytes / 257.0 MiB | 57.42 s | 36 candidates | Unlabelled locations; not confirmed leaks or a precision/recall result |
| fastapi/fastapi snapshot | 3,045 | 23.9 MiB | 9.20 s | 0 candidates | Zero candidates is not proof that the repository contains no secrets |
| fastapi/fastapi plus one local synthetic Groq-format probe | 3,046 | 23.9 MiB | 4.45 s | 1 synthetic candidate | A narrow seeded-path check, not a general accuracy benchmark |

Traversal was complete under the then-documented policy, but binaries, non-UTF-8 files, symlinks/special files and excluded directories were skipped as recorded in the raw results. The runs were not controlled before/after performance comparisons. See [repository-stress.md](repository-stress.md), [stress-vscode.json](stress-vscode.json), [stress-fastapi.json](stress-fastapi.json) and [stress-fastapi-seeded.json](stress-fastapi-seeded.json).

The scanner limits changed during development. For a paper experiment, record the exact commit and live configuration used for every run; do not treat a historical measurement’s limits as current defaults without checking the code/config at that commit.

### 7.2 Test and build evidence

The branch work recorded a focused backend verification run of 116 passed tests and successful frontend lint/build checks. This is engineering regression evidence for the tested subset. It is not an independent detector benchmark, provider coverage evaluation, analyst study, or proof that every code path works against live accounts. Repository documentation contains earlier full-suite counts from before this branch: `docs/ai-detection.md` records 1,221 passed and 2 skipped on 3 November 2026, while an earlier revision of this paper reference recorded 1,250 passed and 2 skipped on 4 November. Those counts differ and predate the current branch snapshot. Re-run and record the full suite at the frozen paper commit before reporting a current full-suite count. The earlier paper draft’s 93.0% retrieval result is also superseded by the dated retrieval fixture values documented in `model-benchmark-pilot.md`; neither value is answer accuracy.

If a paper reports test results, freeze the exact commit, test command, dependency versions, environment, skipped tests and failure count. Do not rerun against live cloud credentials as part of publication preparation without the experiment’s written authorization and safe-account plan.

### 7.3 Evidence status inventory

| Evidence source | Present? | What it supports | What it does not support |
|---|---|---|---|
| Unit/integration test fixtures | Yes | Expected behavior for implemented deterministic paths | Real-world precision/recall or cloud audit completeness |
| Azure nine-scenario definitions | Yes | Registered attack-action classes, taxonomy expectations and cleanup logic | Nine successful live runs or post-exposure recall; current chronology is wrong for that claim |
| Public repository stress observations | Yes | Workload size and latency observations under a specific snapshot policy | Prevalence, candidate validity, detector accuracy or compromise |
| Synthetic Groq-format probe | Yes | Detection of that seeded string in that run | Vendor-wide secret recall |
| Local LLM pilot | Yes, four cases per model | Pilot behavior and observed latency on one machine | Model ranking, accuracy, population-level utility or safe autonomous response |
| Authorized live provider experiments | Some manual integration activity exists; no complete frozen cross-provider dataset in this dossier | Implementation smoke checks for particular configurations | Reproducible cross-platform capture rates or key-level attribution |
| Independent labelled secret benchmark | No current branch artifact establishing one | Nothing until constructed and validated | Precision, recall, F1 or false-positive rate |
| Blinded analyst study | No | Nothing yet | Triage quality, trust, time savings or severity agreement |

## 8. Threats to validity and technical limits

### Construct validity

- A push commit timestamp is not necessarily first exposure. A commit may be private, later made public, removed, force-pushed, forked or mirrored. The current incident record does not reconstruct all those transitions.
- A 30-day provider query is a retrieval window, not a credential exposure window. Collector output is filtered relative to a timestamp estimate, and end time at rotation is not automatically tracked.
- “Event found” is not a universal measure of “credential used.” Account events, application actions and exact-key actions are different evidence levels.
- Severity is an ordinal rule output with heuristic inputs. Without blinded ground truth, it is not an objective compromise likelihood or analyst-quality score.
- A repository candidate is not necessarily a valid or sensitive credential. Context, test fixtures, placeholder values, vendor pattern drift and benign samples matter.

### Internal validity

- Provider logs can be delayed, sampled, disabled, incomplete, scoped differently or changed by vendor API behavior.
- The test API key, principal and reader may have different permissions from real organizations.
- Legitimate account activity may be interleaved with controlled test calls. Provider-level request IDs and isolated test accounts should be used to distinguish them.
- Scenario setup, resource creation and cleanup may themselves generate audit records. Pre-register which actions count and keep setup/cleanup outside the measurement interval.
- Clock skew between GitHub, local host and provider APIs can shift boundaries. Normalize timestamps to UTC and report measured error.

### External validity

- Five collector families do not represent all cloud/SaaS providers, key types, tenants or logging plans.
- The current system is a research prototype using one organisation per installation; its auth/project features do not establish hardened production multi-tenancy. Search, research and repository scans are organisation-wide for admins and security leads rather than project-scoped.
- Local runs, synthetic actions and one organization cannot establish behavior in production-scale enterprises.
- Public repository stress tests use a narrow set of current snapshots, not a random representative sample.

### Conclusion validity

- Current candidate sets are too small and partly synthetic for broad detector accuracy claims.
- The model pilot has four cases per model and no human review.
- There is no current cross-provider confusion matrix for event collection and classification, no calibration curve, no confidence interval, and no blinded severity evaluation.
- Any empty provider timeline must be interpreted alongside collector status, permissions, retention, provider observability and scope.

## 9. Ethics and operational safety

All provider experiments must use accounts and identities owned by the research team or explicitly authorized by the owner. Use sandbox/test modes where available, least-privilege disposable credentials, low-impact calls, budget limits, audit-log retention checks, cleanup verification and a stop condition. Never test a credential found in someone else’s repository by authenticating with it.

For public-repository measurement, request institutional/advisor ethics review and follow platform terms, responsible disclosure, data minimization, safe output and retention controls. Public visibility does not remove privacy or legal responsibilities. Avoid publishing raw secrets, hashes that facilitate guessing, repository paths that re-expose an unrevoked secret, or exact identifiers that enable victim targeting.

For LLM evaluation, treat provider logs, resource names and request metadata as untrusted input. Keep secrets masked; document exactly what leaves the host for hosted inference; use synthetic data unless explicit approval covers the real data flow; and test prompt injection. Preserve a human decision-maker for severity and remediation.

## 10. Recommended main-paper structure

1. **Introduction:** operational problem after a source leak; research questions and bounded contribution.
2. **Background and related work:** secret detection/measurement, leak remediation studies, cloud-key exploitation experiments, provider audit semantics, incident response and attribution.
3. **Threat model and definitions:** attacker can discover a source leak; what “exposure,” “use,” “correlation,” “attribution,” “absence” and “rotation” mean; authorized test assumptions.
4. **System design:** bounded source detection; timestamp provenance; provider adapters; normalizer; event taxonomy; evidence-level labeling; deterministic scoring/reporting; optional model prose separated from evidence.
5. **Provider observability matrix:** action types and identity fields each API exposes, plus collection retention and permission requirements.
6. **Evaluation method:** preregistered scenario/action matrix, test accounts, ground-truth collection, negative controls, repetitions and cleanup.
7. **Results:** event capture and delay, identity-level attribution, pre/post temporal correctness, classification/severity agreement, operational failures and analyst triage utility.
8. **Case studies:** a captured write path, a read-only blind spot, an account-wide ambiguous timeline, and a permission/retention failure.
9. **Optional LLM experiment:** factuality and analyst utility as a separate, carefully scoped study.
10. **Limitations, ethics, deployment implications and conclusion.**

## 11. Paper-ready artifacts to create next

- Freeze a release commit and archive exact configuration, dependencies, provider API versions, fixtures and sanitized run manifests.
- Repair the Azure scenario harness so credential exposure precedes test actions; ensure collection timing accounts for audit-log ingestion delay without redefining the exposure timestamp after the fact.
- Create a ground-truth action manifest with event/request IDs, key IDs, principal IDs, timestamps, expected log behavior and cleanup status.
- Add at least one no-action control and one normal-activity control per provider; include read-only and denied action classes where safe.
- Specify exact attribution levels and do not label account-scoped events “key-level.”
- Verify the same app’s Azure client secrets cannot be distinguished by the current Activity Log collector; separately evaluate whether sign-in credential key IDs are available under authorized Graph permissions and how, if at all, those token events can be joined to later resource activity.
- Evaluate classifier and severity rules against independent human labels, including benign activity and provider-specific blind spots.
- Expand the LLM study with adversarial log strings and blinded reviewers if it remains in scope.
- For a measurement paper, produce a sampling and ethics protocol before collecting a corpus; never validate discovered credentials by using them.
- Replace dated test/build counts with a fresh, frozen, reproducible run only when the authors choose to run and document it.

## 12. Selected literature and technical references

### Secret leakage, detection and remediation

1. Michael Meli, Bradley Reaves and Matthew R. McNiece. “How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories.” NDSS 2019. [DOI](https://doi.org/10.14722/ndss.2019.23418). Large-scale longitudinal study; relevant to detection, discovery and removal measurements.
2. Pascal Krause et al. “Pushed by Accident: A Mixed-Methods Study on Strategies of Handling Secrets in Source Code Repositories.” USENIX Security 2023. [Paper](https://www.usenix.org/system/files/usenixsecurity23-krause.pdf). Developer experiences, risk estimation and remediation needs.
3. Setu Basak, Jameson Cox, Bradley Reaves and Laurie Williams. “A Comparative Study of Software Secrets Reporting by Secret Detection Tools.” ACM/IEEE ESEM 2023. [DOI](https://doi.org/10.1109/ESEM56168.2023.10304853). Detection tool precision/recall trade-offs and error causes.
4. Runhan Feng et al. “Automated Detection of Password Leakage from Public GitHub Repositories.” ICSE 2022. [Paper](https://aoa0.github.io/pubs/icse22.pdf). Contextual password detection and related repository leakage work.

### Exposed credential activity and audit evidence

5. Palo Alto Networks Unit 42. “CloudKeys in the Air: Tracking Malicious Operations of Exposed IAM Keys.” [Report](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/). Controlled cloud-key exposure and observed attacker operations; practitioner research, not a peer-reviewed cross-provider evaluation.
6. AWS CloudTrail documentation. [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html).
7. Google Cloud Audit Logs documentation. [Audit logs overview](https://cloud.google.com/logging/docs/audit).
8. Microsoft Azure Activity Log documentation. [Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log).
9. Microsoft Graph sign-in resource and API permission reference. [signIn resource](https://learn.microsoft.com/en-us/graph/api/resources/signIn?view=graph-rest-beta), [list sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta). Potential future evidence source; not implemented in BreachTrace.
10. Stripe API. [Events API](https://docs.stripe.com/api/events), [CLI request-log stream](https://docs.stripe.com/cli/logs/tail). These are different observation mechanisms with different coverage.
11. Twilio. [Monitor API](https://www.twilio.com/docs/usage/api). Account/event semantics should be confirmed against the exact resources used in a study.

### LLM-assisted incident analysis

12. Daniel Kramer et al. “Integrating Large Language Models into Security Incident Response.” SOUPS 2025. [Paper](https://www.usenix.org/system/files/soups2025-kramer.pdf). Analyst-facing incident summary study.
13. Aniket Anand et al. “Benchmarking and Exploring the Capabilities of LLMs for Attack Investigations” (AuditBench). 2026. [arXiv](https://arxiv.org/abs/2606.10281). Labeled audit-log investigation benchmark.
14. Rabimba Karanjai et al. “Context Contamination in LLM Analysis of Network Security Logs: Poison with Passive Prompt Injection and Mitigation Evaluation.” USENIX Security 2026. [Paper page](https://www.usenix.org/conference/usenixsecurity26/presentation/karanjai). Adversarial log-context risk.

## 13. Writing and reproducibility checklist

- [ ] State which paper direction is primary and avoid claiming an absolute novelty until the related-work review is complete.
- [ ] Identify authors, institution, adviser, intended venue and ethics review status.
- [ ] Define exposure start, exposure end, collection interval, rotation confirmation, event capture, key-level attribution and causal attribution.
- [ ] State that current start is a commit-time estimate and automatic rotation/end-time tracking is not wired into the live path.
- [ ] Correct the scenario chronology before treating Azure runs as post-exposure experiments.
- [ ] Freeze current commit/config/API/dependency versions and include skipped/failed runs.
- [ ] Separate synthetic, public-snapshot, fixture, manual smoke-test and authorized live-experiment evidence.
- [ ] Report detector precision/recall only on independently labelled candidates; include family-specific results and confidence intervals.
- [ ] Report provider observability and identity level separately; never equate an account-level event with proof that one key caused it.
- [ ] Include pre-exposure controls, no-action controls, read-only/denied calls and audit ingestion delays.
- [ ] Evaluate severity against independent analyst labels instead of presenting heuristic weights as validated risk probabilities.
- [ ] Keep model prose out of deterministic evidence fields; assess faithfulness, omission, adversarial prompt injection and human utility separately.
- [ ] Use only authorized test accounts and publish no usable credentials or re-identification-enabling artifacts.
- [ ] Replace dated pilot metrics only with documented runs from the frozen paper artifact.
