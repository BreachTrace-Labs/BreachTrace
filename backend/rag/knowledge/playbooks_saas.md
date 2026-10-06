# SaaS and developer-token playbooks

## How to roll a leaked Stripe secret key
In the Stripe Dashboard open Developers → API keys and use Roll key on the leaked key, setting the old key to expire immediately. Update every deployment with the new key. Where possible use restricted keys (rk_) with only the permissions each service needs, so a leak exposes less.

## What to check after a Stripe key leak
Review Developers → Events and Logs for charges, refunds, payouts and account changes during the exposure window. Check Settings → Bank accounts and payouts: changing the payout destination is the highest-value Stripe attack. Refund or cancel fraudulent charges, and contact Stripe support. Stripe Events record changes only, so customer data that was merely read or exported leaves no event.

## How to rotate a leaked Twilio Auth Token
In the Twilio Console open Account → API keys & tokens, request a secondary Auth Token, update your applications to use it, then promote it to primary, which invalidates the old token. Delete any API keys (SK…) and subaccounts you did not create. Prefer API keys over the main Auth Token in applications, since an API key can be revoked on its own.

## What to check after a Twilio leak
Review Monitor → Logs for messages and calls during the exposure window, especially to countries you do not serve: SMS pumping and premium-rate call fraud are the common abuses. Enable SMS Pumping Protection and restrict Geo Permissions to the countries you need. Message history may contain one-time passcodes; reading it leaves no trace in Twilio's logs.

## How to revoke a leaked GitHub personal access token
Delete the token in GitHub under Settings → Developer settings → Personal access tokens. GitHub automatically revokes many token types it finds in public repositories, but do not rely on it. Review your security log (Settings → Security log) and the repositories the token could reach for unexpected commits, new deploy keys, webhooks or Actions secrets changes. Per-token audit logs are only available to GitHub Enterprise organisations.

## How to revoke a leaked Slack webhook or token
For an incoming webhook, remove it in the Slack app's Incoming Webhooks settings and create a new one. For a bot or user token, revoke it in the app's OAuth & Permissions settings and reinstall the app. Slack records webhook and bot activity in audit logs only on Enterprise Grid plans, so messages sent with a leaked credential usually cannot be listed.

## How to revoke a leaked npm token
List your tokens with `npm token list` and revoke the leaked one with `npm token revoke <TOKEN_ID>`. Check the publish history of every package the token could publish (`npm view <PACKAGE> time`) for versions you did not release, and deprecate or unpublish any malicious version. Require two-factor authentication for publishing.

## How to revoke a leaked SendGrid API key
Delete the key under Settings → API Keys and create a new one with only the permissions it needs (for example Mail Send only). Check sender authentication settings and suppression lists for changes. SendGrid's Email Activity history is a paid add-on, so mail sent with the key may not be listable on the free tier.

## How to revoke a leaked Hugging Face token
Invalidate or refresh the token under Settings → Access Tokens. Check the repositories, models and Spaces the token could write to for unexpected commits. Prefer fine-grained tokens scoped to specific repositories.

## What to do about a leaked database connection string
Change the database user's password immediately (for PostgreSQL: `ALTER USER <USER> WITH PASSWORD '<NEW_PASSWORD>';`) and update every application. Make sure the database is not reachable from the public internet: restrict it to your application's network with firewall rules or private networking. Review the database's own logs for unfamiliar connections and queries; what is recorded depends on how logging was configured before the leak.
