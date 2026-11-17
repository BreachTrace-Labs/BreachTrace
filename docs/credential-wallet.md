# Project credential wallet

An organisation administrator or security lead can add one credential connection per provider to each project. Developers cannot list or modify wallet entries. Credentials are encrypted using AES-256-GCM with a fresh nonce and the `WALLET_ENCRYPTION_KEY` environment variable; the API only returns connection metadata and verification status. The key is a 32-byte hexadecimal value. Back it up securely: changing or losing it prevents decryption of existing connections. Set it using a secret manager on a deployed host.

The wallet does not yet supply credentials to the incident pipeline. Existing collectors still use their current environment configuration. Project-based collection will require explicit integration when incidents are routed to projects.

## Verification

Saving a connection starts an in-process background check. A verified status confirms only the particular operation below; it does not establish every permission required for forensics, nor does it prove that the connection belongs to the account of an exposed key.

- AWS: STS GetCallerIdentity. This checks authentication and does not confirm CloudTrail read permission.
- Google Cloud: request up to one Cloud Audit Logs entry in the service account's project. The service account JSON must include `project_id`.
- Azure: request a resource group from the configured subscription. This does not confirm access to activity logs.
- Stripe: list up to one event using a restricted test or live key with Events read permission. Balance permission is not required.
- Twilio: retrieve the account using its Account SID and Auth Token. Twilio Auth Tokens can grant full account access; use a dedicated subaccount where appropriate.

Verification errors shown in BreachTrace are intentionally generic to avoid disclosing provider responses or credentials. Recheck credentials, network access and permissions with the provider if a check fails. Checks occur in the backend process: if it stops mid-check, a pending connection can be manually verified again after restart.
