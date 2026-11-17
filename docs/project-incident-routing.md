# Project incident routing

Each project owns one GitHub repository. Register its webhook from **Connect**, using an HTTPS URL ending in `/webhook/github`. Registration creates or updates the GitHub hook and stores a separate encrypted project secret. The backend uses `WALLET_ENCRYPTION_KEY` to encrypt webhook secrets; preserve this key across restarts and deployments.

For manual registration, choose a secret of at least 16 characters, configure it in GitHub, and save the same value in Connect for the selected project. Saving a manual secret replaces that project's previous secret; GitHub must be updated to match. GitHub deliveries do not use a JWT. The backend finds the project by the payload's repository name and checks its HMAC signature before processing the push. Unknown repositories are ignored.

New webhook incidents and simulations belong to a project. Developers can list and open incidents for projects where they are members; admins and security leads can access their organisation's projects. Other incident routes, including PDFs and timelines, use the same access check. Refresh and editing remain restricted to admins and security leads. The dashboard displays the selected project's incidents.

Incidents created before projects existed remain unassigned until an admin associates them. On **Projects & team**, select the project and use **Associate older incidents**. Only unassigned records whose GitHub repository matches the project are included. Synthetic records and records without a matching GitHub repository remain unassigned.

Search, research and repository snapshot scans remain restricted to admins and security leads and are not project-filtered. They are disabled if the database contains more than one organisation because their underlying data is not yet scoped. The credential wallet is not yet connected to incident collection; collectors continue to use their existing provider configuration.
