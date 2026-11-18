# GitHub sign-in

GitHub sign-in is optional and only signs in an existing, active BreachTrace user whose email is verified on the GitHub account. An administrator must create or invite the user first. A GitHub account with verified emails matching more than one active BreachTrace account is rejected. Existing roles, project membership and mandatory temporary-password changes remain in effect. The GitHub token is used only to fetch identity and verified emails; BreachTrace does not store it or use it to register repository webhooks.

## Invite a GitHub user

After configuring GitHub sign-in, an organisation administrator can open **Admin → Users → Invite user**, choose **GitHub (verified email)**, and enter an email verified on the recipient's GitHub account. The account has no BreachTrace password; the queued welcome email instructs the recipient to use **Continue with GitHub**. SMTP must be configured for delivery. Add the invited user to the appropriate projects separately. Password invitations continue to require a temporary password change.

## Configure the local app

1. Register a GitHub OAuth app with homepage `http://127.0.0.1:5173` and authorization callback URL `http://127.0.0.1:5173/auth/github/callback`. Use the same host consistently: `localhost` and `127.0.0.1` are different browser origins.
2. Add these values to the private `.env.testing.local` file, without committing it:

   ```dotenv
   GITHUB_OAUTH_CLIENT_ID=<GitHub OAuth app client ID>
   GITHUB_OAUTH_CLIENT_SECRET=<GitHub OAuth app client secret>
   GITHUB_OAUTH_CALLBACK_URL=http://127.0.0.1:5173/auth/github/callback
   ```

3. Restart the backend using `.venv/bin/python scripts/local_dev.py backend`. In the live frontend, choose **Continue with GitHub** on the sign-in page. The user must authorize the `user:email` scope and have a verified GitHub email matching their invitation.

For deployments, use the actual HTTPS frontend origin and register the matching callback URL with GitHub. HTTP callbacks are accepted only on loopback. The browser uses an expiring state value and PKCE; the backend exchanges the authorization code with GitHub and sends only a BreachTrace session token to the browser. The configured GitHub OAuth secret stays on the backend. The existing server-side `GITHUB_TOKEN` is a separate repository/webhook credential.

Changing email ownership can change which GitHub account can sign into an email-matched BreachTrace account. Administrators should deactivate accounts when access should end, and users must retain control of their verified email. For a stronger long-term account-linking policy, bind the GitHub numeric account ID through an authenticated account-linking flow.
