# Project credential wallet

An organisation administrator or security lead can add one credential connection per provider to each project. Developers cannot list or modify wallet entries. Credentials are encrypted using AES-256-GCM with a fresh nonce and the `WALLET_ENCRYPTION_KEY` environment variable; the API only returns connection metadata and verification status. The key is a 32-byte hexadecimal value. Back it up securely: changing or losing it prevents decryption of existing connections. Set it using a secret manager on a deployed host.

For incidents assigned to a project, the pipeline uses that project's verified wallet connection for the matching provider on both initial collection and refresh. A missing, pending, failed or unreadable connection produces a collection error; it never falls back to a global reader or another project's wallet. Save or reverify the connection and refresh the incident. Replacing or removing a connection affects future collections. Legacy incidents without a project continue to use the backend environment configuration.

Choose a reader authorized for the affected provider account and scope. Stripe readers must match the key's test/live mode and the operator must confirm the account; the application cannot independently infer account ownership from a masked key. Twilio association requires an Account SID matching the wallet reader. Azure Activity Log is scoped to the reader's subscription and the separately associated application identity. Verification does not establish ownership of an exposed credential or guarantee that all collection permissions are available.

## Verification

Saving a connection starts an in-process background check. A verified status confirms only the particular operation below; it does not establish every permission required for forensics, nor does it prove that the connection belongs to the account of an exposed key.

- AWS: STS GetCallerIdentity. This checks authentication and does not confirm CloudTrail read permission.
- Google Cloud: request up to one Cloud Audit Logs entry in the service account's project. The service account JSON must include `project_id`.
- Azure: request Activity Log events from the configured subscription. Enter the application (client) ID, not the service principal object ID, and use a matching client secret value, not its key ID. The check does not prove that the reader belongs to an exposed credential's application.
- Stripe: list up to one event using a secret or restricted test or live key with Events read permission. Use a restricted key where possible. Balance permission is not required.
- Twilio: list up to one message using the owning Account SID and either an API key SID and secret or the account Auth Token. This does not establish Calls or Monitor Events access. Service and Environment SIDs identify Serverless resources and cannot authenticate a reader.

Verification errors shown in BreachTrace are intentionally generic to avoid disclosing provider responses or credentials. Recheck credentials, network access and permissions with the provider if a check fails. Checks occur in the backend process: if it stops mid-check, a pending connection can be manually verified again after restart.
