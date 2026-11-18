# Notification delivery

Project administrators and security leads can configure email and Slack destinations in **Admin → Notifications** for the selected project. Configuration changes and removals are recorded in the organization audit log.

## Email setup

Set `SMTP_HOST`, `SMTP_PORT`, and `SMTP_FROM` in the backend environment. If the SMTP relay requires authentication, also set `SMTP_USER` and `SMTP_PASSWORD`. BreachTrace uses STARTTLS with certificate verification and a 15-second connection timeout. Email is disabled when the host or sender is missing. The backend reports only whether SMTP is configured; it never returns the SMTP credentials.

`APP_URL` should be the frontend origin users can reach. Incident links use `/incidents/{id}` on that origin. Invites queue a welcome email and require a password change at first sign-in. The temporary password is encrypted using the wallet key in the queued job, removed after successful or skipped delivery, and expires after 24 hours. Administrators can review and retry failed welcome emails in **Projects & team** while the encrypted value remains available. If it expires, arrange secure access separately.

## Slack setup

Add a Slack incoming webhook URL. Only HTTPS `hooks.slack.com` incoming webhook URLs are accepted. BreachTrace encrypts the URL with `WALLET_ENCRYPTION_KEY` and never returns it after saving. To rotate it, enter the new URL in the replace field. The backend disables redirects and proxy environment inheritance for the outbound request.

## Delivery behavior

- New incidents queue one delivery for each eligible project destination after initial processing. Manual refreshes do not queue creation notices.
- When severity is known, a destination receives alerts at or above its configured minimum (`low`, `medium`, `high`, or `critical`).
- When the severity score is unavailable, only `low` destinations receive a notice, clearly labeled **Not assessed**. An absent score is never treated as low severity.
- Assigning an incident sends an email to the assignee. Inviting a user sends a welcome email after the account is committed.
- Jobs are stored in the database and processed by backend workers with a lease, three attempts and increasing delays. Expired leases are recovered after a restart. Project administrators and security leads can see status, attempt counts and sanitized errors under **Recent deliveries**, and can retry failed deliveries.
- Delivery is at least once: if the backend stops after a provider accepts a message but before the outcome is saved, a retry can send a duplicate. The status means the configured SMTP or Slack endpoint accepted the request; it does not prove a person received or read it. A disabled, deleted or inaccessible destination is marked skipped.
- Alert content includes the credential family and masked hint, repository, commit, and an incident link. It does not include exposed credential values.
