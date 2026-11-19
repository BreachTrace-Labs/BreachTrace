# BreachTrace detection research scope

This document describes the current repository implementation, not an evaluation result.

## Scope and attacker model

The application scans added content in GitHub pushes delivered to a signed webhook and scans eligible UTF-8 text in a current repository snapshot. It looks for supported credential patterns, including some encoded AI-key forms and structured service-account documents. The assumed exposure is a developer or automation committing a credential to a repository. A commit timestamp is only an estimated exposure start; a snapshot does not establish when exposure began. Provider audit evidence depends on authorization and logging configuration.

The repository does not currently establish that a local pre-commit hook or a CI-log scanner is deployed. Encrypted secrets, binary files, process memory, excluded directories and unavailable private repositories are outside the snapshot scanner's coverage. Authenticated private repositories can be scanned when the project has access.

## Credential families

The existing scanner covers AWS access key IDs, Google service-account and Firebase forms, Azure service-principal and client-secret patterns, Stripe, Twilio and other SaaS credentials, plus supported AI-provider key patterns. The exact set and limitations are defined by `backend/detector/patterns.py` and `backend/detector/ai_keys.py`. Generic passwords, personal information and arbitrary private keys are not comprehensively detected; structured Google service-account key documents can contain private-key material.

## Limits

A pattern match does not establish validity, ownership, public exposure or exploitation. The detector does not automatically establish whether all credentials were revoked or rotated. Not all formats or encodings are covered. This implementation does not expose a calibrated numeric four-signal probability; categorical detection confidence is not a probability. Audit records can be incomplete or describe account or application activity rather than an individual key. Collection, sampling and manually labeled candidate sets have selection bias and must not be presented as population-level recall or accuracy.
