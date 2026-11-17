# Project credential wallet

An organisation administrator or security lead can add one credential connection per provider to each project. Developers cannot list or modify wallet entries. Credentials are encrypted using AES-256-GCM with a fresh nonce and the `WALLET_ENCRYPTION_KEY` environment variable; the API only returns connection metadata and verification status. The key is a 32-byte hexadecimal value. Back it up securely: changing or losing it prevents decryption of existing connections. Set it using a secret manager on a deployed host.

The wallet does not yet supply credentials to the incident pipeline. Existing collectors still use their current environment configuration. Project-based collection will require explicit integration when incidents are routed to projects.

## Verification

Saving a connection starts an in-process background check. A verified status confirms only the particular operation below; it does not establish every permission required for forensics, nor does it prove that the connection belongs to the account of an exposed key.

- AWS: STS GetCallerIdentity. This checks authentication and does not confirm CloudTrail read permission.
- Google Cloud: request up to one Cloud Audit Logs entry in the service account's project. The service account JSON must include `project_id`.
- Azure: request Activity Log events from the configured subscription. Enter the application (client) ID, not the service principal object ID, and use a matching client secret value, not its key ID. The check does not prove that the reader belongs to an exposed credential's application.
- Stripe: list up to one event using a secret or restricted test or live key with Events read permission. Use a restricted key where possible. Balance permission is not required.
- Twilio: list up to one message using the owning Account SID and either an API key SID and secret or the account Auth Token. This does not establish Calls or Monitor Events access. Service and Environment SIDs identify Serverless resources and cannot authenticate a reader.

Verification errors shown in BreachTrace are intentionally generic to avoid disclosing provider responses or credentials. Recheck credentials, network access and permissions with the provider if a check fails. Checks occur in the backend process: if it stops mid-check, a pending connection can be manually verified again after restart.
