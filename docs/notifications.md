# Notification delivery

Project administrators and security leads can configure email and Slack destinations in **Admin → Notifications** for the selected project. Configuration changes and removals are recorded in the organization audit log.

## Email setup

Set `SMTP_HOST`, `SMTP_PORT`, and `SMTP_FROM` in the backend environment. If the SMTP relay requires authentication, also set `SMTP_USER` and `SMTP_PASSWORD`. BreachTrace uses STARTTLS with certificate verification and a 15-second connection timeout. Email is disabled when the host or sender is missing. The backend reports only whether SMTP is configured; it never returns the SMTP credentials.

`APP_URL` should be the frontend origin users can reach. Incident links use `/incidents/{id}` on that origin. The invite flow sends the temporary password entered by the administrator in the welcome email, asks the new user to change it immediately, and requires password change at first sign-in. If delivery fails or SMTP is unavailable, the API says so and the admin form retains the temporary password for secure sharing.

## Slack setup

Add a Slack incoming webhook URL. Only HTTPS `hooks.slack.com` incoming webhook URLs are accepted. BreachTrace encrypts the URL with `WALLET_ENCRYPTION_KEY` and never returns it after saving. To rotate it, enter the new URL in the replace field. The backend disables redirects and proxy environment inheritance for the outbound request.

## Delivery behavior

- New incidents are notified once from the initial GitHub webhook processing path, after forensic processing has persisted its severity. Manual refreshes do not send duplicate creation notices.
- When severity is known, a destination receives alerts at or above its configured minimum (`low`, `medium`, `high`, or `critical`).
- When the severity score is unavailable, only `low` destinations receive a notice, clearly labeled **Not assessed**. An absent score is never treated as low severity.
- Assigning an incident sends an email to the assignee. Inviting a user sends a welcome email after the account is committed.
- Delivery failures are logged with only an error class. They do not fail webhook processing or roll back the incident. Delivery is best effort; there is no retry queue or persistent per-message delivery record in this phase.
- Alert content includes the credential family and masked hint, repository, commit, and an incident link. It does not include exposed credential values.
