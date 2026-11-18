"""
GCP Cloud Audit Logs API taxonomy.

Format: "<service>.<resource>.<verb>" → {category, severity, label}

Categories:
  reconnaissance       — Listing, describing, checking permissions
  data_access          — Reading data or secrets
  exfiltration         — Copying, exporting, downloading data outside project
  resource_abuse       — Creating/modifying compute/storage that costs money
  privilege_escalation — IAM, service account key, or role changes
  financial_abuse      — Billing or budget manipulation
  communication_abuse  — PubSub, email, messaging abuse
  code_compromise      — Cloud Functions / Cloud Run code deployment

Severity scale: 1=Low 2=Medium 3=High 4=Critical
"""
from __future__ import annotations

GCP_API_TAXONOMY: dict[str, dict] = {
    # ------------------------------------------------------------------ #
    # Cloud Storage                                                        #
    # ------------------------------------------------------------------ #
    "storage.objects.get": {
        "category": "data_access",
        "severity": 2,
        "label": "Get Object",
    },
    "storage.objects.create": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Upload / Overwrite Object",
    },
    "storage.objects.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Object",
    },
    "storage.objects.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Objects",
    },
    "storage.objects.update": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Update Object Metadata",
    },
    "storage.objects.copy": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Copy Object",
    },
    "storage.buckets.create": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Bucket",
    },
    "storage.buckets.delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Bucket",
    },
    "storage.buckets.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Buckets",
    },
    "storage.buckets.get": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Bucket Metadata",
    },
    "storage.buckets.getStorageLayout": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Bucket Storage Layout",
    },
    "storage.buckets.update": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Update Bucket (IAM / versioning)",
    },
    "storage.buckets.setIamPolicy": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set Bucket IAM Policy",
    },
    "storage.buckets.getIamPolicy": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Bucket IAM Policy",
    },

    # ------------------------------------------------------------------ #
    # IAM / Service Accounts                                               #
    # ------------------------------------------------------------------ #
    "iam.serviceAccountKeys.create": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Create SA Key",
    },
    "iam.serviceAccountKeys.delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete SA Key",
    },
    "iam.serviceAccountKeys.list": {
        "category": "reconnaissance",
        "severity": 2,
        "label": "List SA Keys",
    },
    "iam.serviceAccounts.create": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Create Service Account",
    },
    "iam.serviceAccounts.delete": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Delete Service Account",
    },
    "iam.serviceAccounts.get": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Service Account",
    },
    "iam.serviceAccounts.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Service Accounts",
    },
    "iam.serviceAccounts.setIamPolicy": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set Service Account IAM Policy",
    },
    "iam.serviceAccounts.signBlob": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Sign Blob (token escalation)",
    },
    "iam.serviceAccounts.signJwt": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Sign JWT (token escalation)",
    },
    "iam.serviceAccounts.getAccessToken": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Generate Access Token",
    },
    "iam.roles.create": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Create Custom Role",
    },
    "iam.roles.update": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Update Role Permissions",
    },
    "iam.roles.delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Custom Role",
    },
    "cloudresourcemanager.projects.setIamPolicy": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set Project IAM Policy",
    },
    "cloudresourcemanager.projects.getIamPolicy": {
        "category": "reconnaissance",
        "severity": 2,
        "label": "Get Project IAM Policy",
    },
    "cloudresourcemanager.organizations.setIamPolicy": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set Org IAM Policy",
    },

    # ------------------------------------------------------------------ #
    # Compute Engine                                                       #
    # ------------------------------------------------------------------ #
    "compute.instances.insert": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Insert Instance",
    },
    "compute.instances.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Instance",
    },
    "compute.instances.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Instances",
    },
    "compute.instances.get": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Instance Metadata",
    },
    "compute.instances.start": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Start Instance",
    },
    "compute.instances.stop": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Stop Instance",
    },
    "compute.instances.setMetadata": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Set Instance Metadata (SSH keys)",
    },
    "compute.instances.setServiceAccount": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set Instance Service Account",
    },
    "compute.disks.insert": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Persistent Disk",
    },
    "compute.disks.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Disk",
    },
    "compute.snapshots.insert": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Disk Snapshot",
    },
    "compute.snapshots.delete": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Delete Disk Snapshot",
    },
    "compute.firewalls.insert": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Firewall Rule",
    },
    "compute.firewalls.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Firewall Rule",
    },
    "compute.firewalls.update": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Update Firewall Rule",
    },
    "compute.globalForwardingRules.insert": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Forwarding Rule (LB)",
    },
    "compute.projects.get": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Get Compute Project Info",
    },

    # ------------------------------------------------------------------ #
    # BigQuery                                                             #
    # ------------------------------------------------------------------ #
    "bigquery.tables.getData": {
        "category": "data_access",
        "severity": 2,
        "label": "Query Table Data",
    },
    "bigquery.tables.create": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Table",
    },
    "bigquery.tables.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Table",
    },
    "bigquery.tables.export": {
        "category": "data_access",
        "severity": 3,
        "label": "Export Table to GCS",
    },
    "bigquery.tables.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Tables",
    },
    "bigquery.datasets.create": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Dataset",
    },
    "bigquery.datasets.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Dataset",
    },
    "bigquery.jobs.create": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Query Job",
    },

    # ------------------------------------------------------------------ #
    # Secret Manager                                                       #
    # ------------------------------------------------------------------ #
    "secretmanager.versions.access": {
        "category": "data_access",
        "severity": 4,
        "label": "Access Secret Version",
    },
    "secretmanager.secrets.create": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Create Secret",
    },
    "secretmanager.secrets.delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Secret",
    },
    "secretmanager.secrets.list": {
        "category": "reconnaissance",
        "severity": 2,
        "label": "List Secrets",
    },

    # ------------------------------------------------------------------ #
    # Cloud Key Management Service (KMS)                                  #
    # ------------------------------------------------------------------ #
    "cloudkms.cryptoKeys.create": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Create KMS Key",
    },
    "cloudkms.cryptoKeyVersions.destroy": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Destroy KMS Key Version",
    },
    "cloudkms.cryptoKeyVersions.useToDecrypt": {
        "category": "data_access",
        "severity": 4,
        "label": "Decrypt with KMS Key",
    },
    "cloudkms.cryptoKeyVersions.useToEncrypt": {
        "category": "data_access",
        "severity": 3,
        "label": "Encrypt with KMS Key",
    },
    "cloudkms.keyRings.create": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Create KMS Key Ring",
    },

    # ------------------------------------------------------------------ #
    # Cloud Run / Cloud Functions (code deployment)                       #
    # ------------------------------------------------------------------ #
    "run.services.create": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Deploy Cloud Run Service",
    },
    "run.services.replace": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Update Cloud Run Service",
    },
    "run.services.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Cloud Run Service",
    },
    "cloudfunctions.functions.create": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Create Cloud Function",
    },
    "cloudfunctions.functions.update": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Update Cloud Function",
    },
    "cloudfunctions.functions.delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Cloud Function",
    },

    # ------------------------------------------------------------------ #
    # GKE / Container                                                     #
    # ------------------------------------------------------------------ #
    "container.clusters.create": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create GKE Cluster",
    },
    "container.clusters.delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete GKE Cluster",
    },
    "container.clusters.update": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Update GKE Cluster",
    },
    "container.pods.create": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Kubernetes Pod",
    },

    # ------------------------------------------------------------------ #
    # Pub/Sub                                                              #
    # ------------------------------------------------------------------ #
    "pubsub.topics.create": {
        "category": "communication_abuse",
        "severity": 2,
        "label": "Create Pub/Sub Topic",
    },
    "pubsub.subscriptions.create": {
        "category": "communication_abuse",
        "severity": 2,
        "label": "Create Pub/Sub Subscription",
    },
    "pubsub.topics.publish": {
        "category": "communication_abuse",
        "severity": 2,
        "label": "Publish to Pub/Sub Topic",
    },

    # ------------------------------------------------------------------ #
    # Billing / Financial                                                  #
    # ------------------------------------------------------------------ #
    "billing.accounts.close": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Close Billing Account",
    },
    "billing.budgets.create": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create Billing Budget",
    },
    "billing.budgets.update": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Update Billing Budget",
    },

    # ------------------------------------------------------------------ #
    # Cloud SQL                                                            #
    # ------------------------------------------------------------------ #
    "cloudsql.instances.create": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Cloud SQL Instance",
    },
    "cloudsql.instances.delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Cloud SQL Instance",
    },
    "cloudsql.instances.update": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Update Cloud SQL Instance",
    },
    "cloudsql.databases.delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Database",
    },
    "cloudsql.users.create": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Create DB User",
    },

    # ------------------------------------------------------------------ #
    # Logging / Monitoring                                                 #
    # ------------------------------------------------------------------ #
    "logging.sinks.create": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create Log Sink",
    },
    "logging.sinks.update": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Update Log Sink",
    },
    "logging.logEntries.list": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "List Log Entries",
    },
    "monitoring.alertPolicies.create": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Create Alert Policy",
    },
    "monitoring.alertPolicies.delete": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Delete Alert Policy",
    },
}


# Provider-documented audit method names whose wire format differs from the
# existing short taxonomy keys. Service scoping avoids matching unrelated APIs.
_GCP_SERVICE_ALIASES = {
    ('secretmanager.googleapis.com', 'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion'): 'secretmanager.versions.access',
    ('cloudkms.googleapis.com', 'Decrypt'): 'cloudkms.cryptoKeyVersions.useToDecrypt',
    ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccountKey'): 'iam.serviceAccountKeys.create',
    ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccount'): 'iam.serviceAccounts.create',
}


def gcp_taxonomy_entry(action: str, service: str | None = None) -> dict | None:
    alias = _GCP_SERVICE_ALIASES.get((service, action))
    if service == 'compute.googleapis.com' and action.startswith(('v1.compute.', 'beta.compute.')):
        alias = action.split('.', 1)[1]
    return GCP_API_TAXONOMY.get(alias or action)

