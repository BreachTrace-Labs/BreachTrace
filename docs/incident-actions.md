# Incident actions and audit

A project member can dismiss an incident with one of four categories and an explanation of at least 10 characters. Dismissal records who performed it and when; it does not delete evidence or assert that an exposed credential is safe. Dismissed incidents remain in the API and can be shown on the dashboard with **Show dismissed incidents**.

An organisation admin or security lead can assign an incident to an active member of the incident's project. The assignee appears on the incident and dashboard. Assignment emails are not sent yet; notification delivery is part of the next phase.

Incident views, dismissals, assignments and refreshes create audit entries, as do authentication, user and project management, wallet operations, and snapshot starts. Audit metadata omits credentials and dismissal explanations. Admins can filter and page through the organisation log in **Projects & team**. Admins and security leads can view the audit trail for an incident they can access. Sensitive changes and their audit records are committed together.
