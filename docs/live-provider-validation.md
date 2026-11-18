# Live provider validation

This records read-only checks against the isolated local test installation on
2026-11-18. Counts describe one configured project and its selected Azure
application; they are not a cross-provider evaluation or proof of complete log
coverage. No provider credentials or individual event contents are included.

| Area | Result | Scope and remaining work |
| --- | --- | --- |
| Azure Activity Log reader | Passed | The configured reader successfully queried Activity Log. A direct seven-day collection for one associated application returned 140 matching events, including 108 with a source IP and 140 with a resource. This is application-level correlation. The incident refresh workflow and ground-truth event attribution were not tested in this check. |
| Azure Graph sign-ins | Blocked by provider | Graph returned an authorization denial. Check the reader's `AuditLog.Read.All` application permission and admin consent, tenant/license and other access policies, then retry. This does not prove that no sign-ins exist. |
| Twilio Messages reader | Failed | The provider rejected the configured reader or its permission. Correct the project connection and reverify. No Messages, Calls, Monitor Events, financial impact or end-to-end incident collection was established by this check. |
| AWS | Not tested | No AWS project reader was configured. |
| GCP | Not tested | No GCP project reader was configured. The key-attribution implementation has synthetic tests but no live-key evidence validation here. |
| Stripe | Not tested | No Stripe project reader was configured. Existing incidents alone do not establish a currently usable reader, account ownership or live collection coverage. |

The read-only checks did not modify wallet verification status, refresh existing
incidents, create provider resources or generate financial transactions. No
assertion is made about real-time capture, missing permissions beyond the failed
checks, empty-log handling, partial collection, financial-impact correctness,
exposure closure or the other providers' live workflows. Validate those using
owner-controlled test projects, ground-truth event timestamps and sandbox modes
where supported. Never put credentials or provider response bodies in this file.
