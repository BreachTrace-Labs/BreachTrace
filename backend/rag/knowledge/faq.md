# BreachTrace FAQ

## What does BreachTrace do?
BreachTrace watches signed GitHub pushes for credential candidates. A commit timestamp is used as an estimated exposure start; it does not prove the repository was public or establish first exposure. When supported, BreachTrace collects available provider records, classifies events, scores the incident and writes a report. Records can describe an account or application rather than use of the detected credential.

## What is the difference between Tier 1 and Tier 2 credentials?
Tier 1 means BreachTrace has a supported collection path with enough identity and access information: AWS, Google Cloud and Firebase, Azure, Stripe or Twilio. Tier 2 means the current workflow only detects the candidate and cannot collect its activity. Available APIs, permissions and attribution differ by provider; a Tier 1 label does not prove the credential was used or that all activity can be reconstructed.

## Why is there no activity timeline for my incident?
Either the credential is Tier 2 (its platform has no queryable audit log), or the audit log recorded nothing in the investigation window. Neither means the credential went unused. Audit logs have blind spots, can lag by several minutes, and some only record writes. Treat every leaked credential as compromised and rotate it.

## Does an empty audit log mean the credential was not used?
No. It means no activity was recorded. CloudTrail skips S3 data events unless they were enabled, Google Cloud Data Access logs are off by default, Azure Activity Log covers control-plane operations only, Stripe Events record state changes but not reads, and Twilio lists messages and calls but not reads of message history. Use the refresh button after a few minutes, since logs can arrive late.

## What is the exposure window?
The triggering commit timestamp is an estimated exposure start, not proof of public visibility or first exposure. The live workflow does not automatically confirm the rotation time for ordinary incidents. Collection requests up to 30 days of recent history through collection time, subject to provider retention and access. Events before the estimated start are context and do not contribute to post-exposure scoring. Empty results do not establish non-use.

## How is the overall severity calculated?
Every incident is scored Low, Medium, High or Critical. Each action is classified into an impact category with a weight from 1 (low) to 4 (critical). Any privilege escalation, data exfiltration or code compromise makes the incident Critical. Financial abuse makes it High, or Critical when any action weighs 3 or more. Otherwise the highest action weight decides: 4 Critical, 3 High, 2 Medium, 1 Low.

## What are the impact categories?
Reconnaissance (listing and describing things, low), data access (reading data, medium), data exfiltration (bulk reading, critical), resource abuse (creating or changing resources, high), privilege escalation (creating keys, granting permissions, critical), financial abuse (charges, payouts, purchases), communication abuse (sending messages or placing calls) and code compromise (publishing packages, force pushes).

## When is data access escalated to exfiltration?
When the same read action is repeated from the same IP address at least 5 times in the window (20 times for Twilio, where small volumes are normal traffic), the reads are treated as bulk data exfiltration and scored Critical.

## Are the financial figures exact?
Stripe figures are real money: amounts actually charged, refunded or paid out, counted once per payment. Twilio uses the price Twilio billed when it is available, otherwise a list-price estimate. AWS, Google Cloud and Azure figures are order-of-magnitude estimates from public list prices for the resources created, labelled as estimates.

## When does BreachTrace flag GDPR, PCI-DSS or SOC 2?
GDPR is flagged when data was read or exfiltrated from a resource whose name suggests personal data (users, customers, emails, patients and similar). PCI-DSS is flagged for any financial abuse, or for access to payment-related resources. SOC 2 is flagged for privilege escalation, exfiltration or resource abuse. These are prompts to check your obligations, not legal conclusions.

## Who writes the incident report?
Every report starts from verified facts computed in code: severity, counts, resources, money and the remediation checklist. A template writes the first version immediately. When the local BreachTrace report model is installed it rewrites the prose on this computer, and its output is only accepted if every name, IP address and amount it mentions is in the facts. The report badge shows which writer produced the text.

## Does BreachTrace send my data anywhere?
Search retrieves passages locally. You can optionally ask the selected model to write an answer from those passages; cloud models receive the question and selected passages. Reports use the model chosen in Settings: a local model keeps report inference on the backend machine, while a cloud model sends incident fact sheets to that provider. Deterministic reports need no AI service. Model response quality depends on the selected model; verify conclusions against cited evidence. BreachTrace calls platform APIs to collect evidence and GitHub to read repository content. Detected AI keys are not validated against their providers.

## How do I search?
Ask in plain English. Questions about your incidents work best with a platform, time or severity, for example "critical AWS incidents this week", "stripe incidents in the last 7 days" or "which incidents had financial abuse". How-to questions search this knowledge base, for example "how do I rotate a Twilio auth token" or "why is there no timeline for a GitHub token".
