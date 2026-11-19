# BreachTrace P0 research results

**Finding.** In the paired GCP development cases, BreachTrace and the explicit-key-field baseline each recovered both evidence-supported target operations and identified both evidenced sibling operations. The principal-and-time baseline assigned five non-target operations to the target. The investigator could see the distinction in the timeline. Every deterministic report used the same wording, including in the target, sibling and unresolved cases. Report severity and blast radius also stayed the same.

**Scope.** Frozen application revision `7fffd136b8733cfe6e091d3c15caa7f1ff377dff`. The paired dataset is [timeline cases v1](protocols/timeline-cases-v1.md). Source-specific mapper inputs and offline pipeline inputs are synthetic. The separate historical Twilio dataset is a user-supplied normalized experiment export. The original provider responses and an independent key-use ledger were unavailable for adjudication. No vendor examples enter the totals. There are zero independently ledgered native cases in the evaluation. These results support a controlled implementation finding and a descriptive Twilio case series.

## EXP-01. What evidence was available?

### Historical Twilio scenarios

The supplied normalized JSON matched the SHA-256 digest in its export manifest (`5d4c49ce7bd443bdbdf5686e56a7af3ab73f921618dd2d129d60df9d6edaa178`). It contains seven scenarios across five distinct reported account IDs. These are repeated experimental observations with unestablished independence. The execution-side measure is **recorded API attempts**, including attempts in failed scenarios. The evidence-side measure is **retained normalized events**. All six retained events identify Twilio Monitor as the source and an account as the actor. Zero of six identify an acting API key. An API key appearing as the resource created or deleted does not identify the actor.

| Opaque case | Mode | Recorded outcome | Recorded API attempts | Retained events |
|---|---|---|---:|---:|
| T01 | Test | API only | 4 | 0 |
| T02 | Test | API only | 1 | 0 |
| T03 | Test | API only | 20 | 0 |
| T04 | Live | Complete | 4 | 0 |
| T05 | Live | Complete | 3 | 4 |
| T06 | Live | Failed | 3 | 2 |
| T07 | Live | Blocked | 0 | 0 |
| **Total** | | | **35** | **6** |

T05 recorded key creation and application creation and update. Its Monitor events have corresponding action names, plus key deletion. T06 recorded account creation, account update and key creation. Its retained events describe account update and key creation. Action agreement is a candidate match only. No archived original response or independently verified per-operation join establishes exact matches, acquisition completeness or total native records available. Only T05 is marked eligible for complete event reconstruction in the export. T06 contributes partial evidence. Zero retained events for T01–T04 and T07 describe the export's contents. The test cases have persistence limitations, and the blocked case has no recorded attempt. A coverage fraction using six events over 35 attempts would have no valid interpretation.

### Source-specific mapper checks

| Provider and source | Constructed input records | Persisted records | Persisted records retaining explicit acting-key ID |
|---|---:|---:|---:|
| AWS CloudTrail LookupEvents | 1 | 1 | 1 |
| AWS CloudTrail trail file | 1 | 1 | 1 |
| GCP Cloud Audit Logs | 2 | 2 | 1 |
| Azure Activity Log | 2 | 2 | 0 |
| Stripe Events | 2 | 2 | 0 |
| Twilio Messages | 2 | 2 | 0 |
| Twilio Calls | 2 | 2 | 0 |
| Twilio Monitor | 1 | 1 | 0 |

For **each** source above, independent case count is zero. Operations actually executed, operations with a matching native record, total available native records and records acquired from a provider were unmeasured. Records were supplied directly to mappers. In GCP the second input omitted the key field. Azure, Stripe and Twilio inputs supplied application or account evidence. Their source IDs survived in retained raw evidence despite an empty normalized source-record ID. Missing explicit outcome mapped to success in both AWS cases and in selected Azure and Twilio inputs. These checks characterize the specific inputs. They do not establish provider-wide availability. [AWS/GCP field observations](results/raw/field-retention.csv) · [Azure/Stripe/Twilio field observations](results/raw/saas-azure-mapping.csv)

## EXP-02. Which key was used?

Twelve constructed operations across six paired patterns comprise five target operations, five same-principal sibling operations and two unrelated-principal operations. Fixture construction supplies this truth. The target is the key associated with the incident. An assignment earns warranted-target credit only when the visible actor, usable key identifier and incident association support it.

| Arm | Warranted target / 5 | Sibling wrongly called target / 5 | Unrelated wrongly called target / 2 | Abstentions / 12 |
|---|---:|---:|---:|---:|
| BreachTrace | 2 | 0 | 0 | 8 |
| Always abstain | 0 | 0 | 0 | 12 |
| Principal and time | 2 | 5 | 0 | 2 |
| Explicit native fields | 2 | 0 | 0 | 8 |

Three true target uses remained unresolved in BreachTrace, one each with a missing key, malformed key and missing incident association. Principal-and-time assigned these three to the target by coincidence. The paired decisions below use T for target, O for another key and U for abstention. The full [decision file](results/raw/timeline-decisions.csv) records each arm separately.

## EXP-03. What did the investigator see?

The twelve EXP-02 operations were replayed individually through the frozen GCP mapper, stub acquisition, actual pipeline, in-memory persistence and incident-detail route. All twelve completed. Each input was enriched with the same resource and success outcome and a distinct stable source-record ID for linkage. The stub returns the supplied record even in the unrelated-principal control. This tests downstream behavior if an unrelated record reaches the pipeline. It does not test the upstream provider query.

| Case | Truth | BT | Always abstain | Principal/time | Native fields | Timeline key label | Supporting record ID (unique prefix) |
|---|---|---|---|---|---|---|---|

| target-0 | target | T | U | T | T | matched | 933361c12e55 |
| target-1 | target | T | U | T | T | matched | 3a1f3e075cbd |
| sibling-0 | sibling | O | U | T | O | different_key | 90deb11b3887 |
| sibling-1 | sibling | O | U | T | O | different_key | c85d6d2f0ac0 |
| missing-0 | target | U | U | T | U | unavailable | 1d8bcba36912 |
| missing-1 | sibling | U | U | T | U | unavailable | 124dddc3ac7a |
| malformed-0 | target | U | U | T | U | unavailable | 63b9e60b4953 |
| malformed-1 | sibling | U | U | T | U | unavailable | 0b1f1098c331 |
| unrelated-0 | unrelated | U | U | U | U | unavailable | 2f03ac417fd8 |
| unrelated-1 | unrelated | U | U | U | U | unavailable | 23fdfda86f7e |
| no_association-0 | target | U | U | T | U | absent | 401f3b7ad921 |
| no_association-1 | sibling | U | U | T | U | absent | 17f307e54ee1 |

All twelve incidents had Medium severity (stored value 2) and a blast radius of one event, one success, zero failures and one resource. The timeline distinguished four key-specific cases. Across these four, **0/4 reports communicated the timeline’s specific-key decision**. All twelve reports were byte-identical. The exact shared report follows.

~~~~text
## Executive Summary

A Google Cloud service account key (fixture) was detected in repository content. The commit timestamp is an estimated exposure start; rotation is not confirmed by this report. Cloud Audit Logs recorded 1 event(s) between 2026-01-01 00:00:00 UTC and 2026-01-01 00:00:00 UTC, the most serious being data access. Overall severity: Medium.

## What Happened

- 2026-01-01 00:00:00 UTC: Get Object (storage.objects.get) on projects/_/buckets/demo/objects/object.

## Business Impact

Cloud Audit Logs do not establish billing charges or financial loss. No source IP addresses were available in the collected events. Activity is matched to a service account, not necessarily a particular key. Data Access logs depend on the service and logging configuration.

## Remediation Checklist

1. ☐ Revoke the exposed credential now: gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SERVICE_ACCOUNT_EMAIL>
2. ☐ Check whether the data that was read (projects/_/buckets/demo/objects/object) contains personal or payment data
3. ☐ Review Cloud Audit Logs for any further activity: gcloud logging read 'protoPayload.authenticationInfo.principalEmail="<SERVICE_ACCOUNT_EMAIL>"'
4. ☐ Purge the credential from git history (rotation alone leaves it readable in past commits)
5. ☐ Enable secret scanning on the repository to catch the next leak before it is pushed
~~~~

### Claim-level assessment

These are the report author's preliminary judgments from the artifacts. Independent reviewer judgments and agreement are pending. Each row in the case table identifies the supporting record for that incident. Full record IDs, exact report text, labels and blast-radius objects are retained in the [paired surface captures](results/raw/paired-reports.json).

| Claim and scope | Judgment | Evidence |
|---|---|---|
| Timeline matched target (specific key) | Supported in target-0/1 | Each row's record contains the matching key resource and principal, with the fixture's target association. |
| Timeline identified another key (specific key) | Supported in sibling-0/1 | Each row's record identifies a sibling key under the same principal. |
| Timeline withheld a target label (specific key) | Supported in remaining eight | Missing or malformed field, unrelated actor, or unavailable association, as indicated by case name. |
| One successful Get Object on one resource (observed activity) | Supported in all twelve | Each row's linked record supplies action, resource, timestamp and success. |
| Activity matched to a service account (principal) | Supported literally in all twelve. Ambiguous in unrelated-0/1 if read as referring to the incident principal | Both unrelated records name another principal. An interpretation assigning their action to the incident principal is contradicted. |
| Medium severity (incident) | Supported as a computed value in all twelve | Persisted severity and blast-radius classification agree. Attack impact has no independent adjudication. |
| A key was detected in repository content (exposure) | Unsupported by these pipeline inputs in all twelve | The harness seeded an incident. No VCS detection record was supplied. |
| Confirmed financial loss or compromise (account or key) | No affirmative claim | No financial or independent compromise evidence entered the replay. |

**Unsupported key-use assertions in the reports: 0/12** by preliminary textual assessment. If “key-specific assertion” also includes the claim that a key was detected in a repository, **12/12** contain that unverified setup assertion. The distinction matters because an accurately scoped narrative can still omit useful key evidence. Neither figure is an independently reviewed error rate. Remediation instructions were excluded from the factual-claim count.

**Two worked cases.** In target-0 the incident association and source key agree. The timeline showed `matched`, but the report described only a service account. In sibling-0 the actor principal, action, timestamp and resource are the same as target-0. The record names another key and the timeline showed `different_key`. The report and Medium severity were identical to target-0. A reader of the report alone could not recover the difference.

### Other investigator outputs

One additional controlled pipeline case each for Azure, Stripe and Twilio completed. Azure produced Low severity for one application-scoped activity, Stripe Critical for one account-scoped payment event, and Twilio Medium for one account-scoped messaging event. The reports state their respective attribution limits. Exact wording and blast radius are in the [three provider captures](results/raw/provider-pipelines.json). A separate [GCP two-record capture](results/raw/gcp-pipeline-replay.json) shows target and sibling events combined into a single incident summary. AWS has mapper results here only. These additional cases are outside the twelve paired judgments.

### Uncertainty and reproducibility

No independent native account or incident qualified for paired key-use analysis. The seven historical scenarios represent five account IDs, with two scenarios contributing events. The twelve GCP cases share one constructed incident principal and six case patterns. There is no held-out sample, independent baseline author, blinded review or justified population confidence interval. The Twilio export, GCP paired replay and provider mapper checks measure different endpoints and have separate denominators. A claim about real-world cross-provider attribution accuracy remains open until native records from at least two distinct sources can be joined to independent per-operation key truth.

[Paired replay program](reproducibility/paired_reports.py) · [Paired case protocol](protocols/timeline-cases-v1.md) · [Run metadata](manifests/environment.json)
