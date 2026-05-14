"""GCP API method taxonomy.

Keys use Cloud Audit Logs-style method names (dot-separated, lowercase):
  "service.resource.verb"
Examples:
  - "storage.objects.get"
  - "iam.serviceAccountKeys.create"
  - "compute.instances.insert"

Categories (must match exactly — classifier/rules.py uses these strings):
  - reconnaissance       (severity 1)
  - data_access          (severity 2)
  - resource_abuse       (severity 3)
  - privilege_escalation (severity 4)
  - exfiltration         (severity 4)

Notes on bulk escalation
------------------------
The classifier applies a bulk-access escalation rule (same api_action + same
source IP >= threshold) that upgrades *data_access* to *exfiltration*.
For that to work, "getData"-style reads should be categorized as data_access
initially, not exfiltration.

Corrections vs. original taxonomy
----------------------------------
- storage.objects.compose       : data_access → resource_abuse (it is a write/create)
- iam.serviceAccounts.implicitDelegation : removed (not a real audit log method;
    replaced by iam.serviceAccounts.actAs which IS the actual logged permission)
- compute.instances.setServiceAccount   : resource_abuse → privilege_escalation
    (reassigning a VM SA to a higher-privileged one is a classic privesc path)
- cloudfunctions.functions.create/update: resource_abuse → privilege_escalation
    (deploying/updating a function that runs as a privileged SA enables privesc)
- run.services.create/update            : resource_abuse → privilege_escalation
    (same reasoning as Cloud Functions)
- cloudkms.cryptoKeys.encrypt           : privilege_escalation → resource_abuse
    (encrypt does not expose data or elevate access; decrypt stays at severity 4)
- iam.serviceAccountKeys.delete         : privilege_escalation → resource_abuse
    (key deletion is defense evasion / destruction, not privilege escalation)
- iam.roles.delete                      : privilege_escalation → resource_abuse
    (role deletion removes access rather than granting it)
- logging.logEntries.list               : reconnaissance → data_access
    (logs routinely contain tokens, credentials in URLs, and PII)
- bigquery.jobs.create                  : kept at exfiltration (4) — every BQ
    query uses this method, so expect false-positive volume; a downstream job-type
    filter (EXTRACT vs QUERY) is recommended in the classifier to reduce noise
- Added missing high-risk methods (see ADDED sections below)
"""

VALID_CATEGORIES: set[str] = {
	"reconnaissance",
	"data_access",
	"exfiltration",
	"resource_abuse",
	"privilege_escalation",
}

VALID_SEVERITIES: set[int] = {1, 2, 3, 4}


# =============================================================================
# CONTROL-PLANE + DATA-PLANE (GCP Cloud Audit Logs)
# =============================================================================
GCP_API_TAXONOMY: dict[str, dict] = {

	# =========================================================================
	# RECONNAISSANCE (Severity 1)
	# Metadata enumeration and low-impact discovery.
	# =========================================================================

	# Cloud Storage
	"storage.buckets.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Buckets",
	},
	"storage.buckets.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Bucket Metadata",
	},
	"storage.objects.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Objects",
	},
	"storage.objects.getIamPolicy": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Object IAM Policy",
	},
	"storage.buckets.getIamPolicy": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Bucket IAM Policy",
	},
	"storage.hmacKeys.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List HMAC Keys",
	},

	# Compute Engine
	"compute.instances.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List VM Instances",
	},
	# Explicit override: "get" is metadata here; avoid data_access.
	"compute.instances.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get VM Instance Metadata",
	},
	"compute.disks.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Disks",
	},
	"compute.disks.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Disk Metadata",
	},
	"compute.snapshots.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Snapshots",
	},
	"compute.snapshots.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Snapshot Metadata",
	},
	"compute.firewalls.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Firewall Rules",
	},
	"compute.firewalls.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Firewall Rule",
	},
	"compute.networks.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List VPC Networks",
	},
	"compute.subnetworks.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Subnetworks",
	},
	"compute.addresses.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Reserved IP Addresses",
	},
	"compute.forwardingRules.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Forwarding Rules",
	},
	"compute.backendServices.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Backend Services",
	},
	"compute.urlMaps.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List URL Maps",
	},
	"compute.sslCertificates.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List SSL Certificates",
	},

	# IAM
	"iam.serviceAccounts.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Service Accounts",
	},
	"iam.serviceAccounts.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Service Account",
	},
	"iam.roles.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List IAM Roles",
	},
	"iam.roles.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get IAM Role",
	},
	"iam.serviceAccountKeys.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Service Account Keys",
	},
	"iam.policies.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get IAM Policy",
	},
	"cloudresourcemanager.projects.getIamPolicy": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Project IAM Policy",
	},
	"cloudresourcemanager.folders.getIamPolicy": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Folder IAM Policy",
	},
	"cloudresourcemanager.organizations.getIamPolicy": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Organization IAM Policy",
	},

	# BigQuery
	"bigquery.datasets.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Datasets",
	},
	"bigquery.tables.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Tables",
	},
	"bigquery.tables.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Table Metadata",
	},

	# Secret Manager
	"secretmanager.secrets.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Secrets",
	},
	"secretmanager.secrets.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Secret Metadata",
	},
	"secretmanager.versions.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Secret Versions",
	},

	# GKE (Google Kubernetes Engine)
	"container.clusters.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List GKE Clusters",
	},
	"container.clusters.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get GKE Cluster",
	},
	"container.nodePools.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Node Pools",
	},
	"container.nodePools.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Node Pool",
	},

	# Pub/Sub
	"pubsub.topics.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Pub/Sub Topics",
	},
	"pubsub.subscriptions.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Pub/Sub Subscriptions",
	},

	# Cloud Logging & Monitoring
	"logging.sinks.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Logging Sinks",
	},
	# FIXED: was reconnaissance (1); logs frequently contain tokens, credentials
	# in request URLs, and PII — treat as data_access (2). See data_access section.
	"monitoring.metricDescriptors.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Metric Descriptors",
	},
	"monitoring.alertPolicies.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Alert Policies",
	},

	# Cloud Run & Cloud Functions
	"run.services.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Cloud Run Services",
	},
	"run.services.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Cloud Run Service",
	},
	"cloudfunctions.functions.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Cloud Functions",
	},
	"cloudfunctions.functions.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Cloud Function",
	},

	# Cloud SQL
	"cloudsql.instances.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Cloud SQL Instances",
	},
	"cloudsql.instances.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get Cloud SQL Instance Metadata",
	},
	"cloudsql.users.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Cloud SQL Users",
	},

	# KMS
	"cloudkms.keyRings.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List KMS Key Rings",
	},
	"cloudkms.cryptoKeys.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List KMS Crypto Keys",
	},

	# ADDED: Project/org enumeration — standard first step in GCP recon
	"cloudresourcemanager.projects.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Projects",
	},
	"cloudresourcemanager.folders.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Folders",
	},
	"cloudresourcemanager.organizations.search": {
		"category": "reconnaissance", "severity": 1,
		"label": "Search Organizations",
	},

	# ADDED: Enumerate enabled APIs — attackers map attack surface before acting
	"serviceusage.services.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Enabled APIs/Services",
	},
	"serviceusage.services.get": {
		"category": "reconnaissance", "severity": 1,
		"label": "Get API/Service Status",
	},

	# ADDED: VPC Service Controls — reveals data perimeter topology
	"accesscontextmanager.accessPolicies.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List VPC-SC Access Policies",
	},
	"accesscontextmanager.servicePerimeters.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List VPC Service Control Perimeters",
	},

	# ADDED: Org policy enumeration — reveals guardrails (and gaps)
	"orgpolicy.policies.list": {
		"category": "reconnaissance", "severity": 1,
		"label": "List Organization Policies",
	},

	# =========================================================================
	# DATA ACCESS (Severity 2)
	# Single-object reads and interactive data access.
	# =========================================================================

	# Cloud Storage
	"storage.objects.get": {
		"category": "data_access", "severity": 2,
		"label": "Read Object",
	},
	"storage.objects.getMetadata": {
		"category": "data_access", "severity": 2,
		"label": "Read Object Metadata",
	},
	# FIXED: was data_access — compose is a write (creates a new object by
	# concatenating existing ones). Moved to resource_abuse (3).

	# BigQuery (initially data_access; bulk escalation may upgrade to exfiltration)
	"bigquery.tables.getData": {
		"category": "data_access", "severity": 2,
		"label": "Read Table Data",
	},
	"bigquery.jobs.getQueryResults": {
		"category": "data_access", "severity": 2,
		"label": "Get Query Results",
	},

	# Cloud Logging
	# FIXED: was reconnaissance (1); query results frequently contain credentials,
	# tokens embedded in request URLs, and PII. Elevated to data_access (2).
	"logging.logEntries.list": {
		"category": "data_access", "severity": 2,
		"label": "Query Log Entries",
	},

	# =========================================================================
	# RESOURCE ABUSE (Severity 3)
	# Creates/deletes/starts/stops and operational mutations.
	# =========================================================================

	# Cloud Storage
	# FIXED: compose was incorrectly in data_access; it is a write operation.
	"storage.objects.compose": {
		"category": "resource_abuse", "severity": 3,
		"label": "Compose Object (Write)",
	},
	"storage.objects.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Object",
	},
	"storage.objects.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Object",
	},
	"storage.buckets.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Bucket",
	},
	"storage.buckets.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Bucket",
	},
	"storage.buckets.update": {
		"category": "resource_abuse", "severity": 3,
		"label": "Update Bucket",
	},

	# Compute Engine
	"compute.instances.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create VM Instance",
	},
	"compute.instances.start": {
		"category": "resource_abuse", "severity": 3,
		"label": "Start VM Instance",
	},
	"compute.instances.stop": {
		"category": "resource_abuse", "severity": 3,
		"label": "Stop VM Instance",
	},
	"compute.instances.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete VM Instance",
	},
	"compute.instances.setMetadata": {
		"category": "resource_abuse", "severity": 3,
		"label": "Set VM Metadata",
	},
	"compute.instances.setTags": {
		"category": "resource_abuse", "severity": 3,
		"label": "Set VM Network Tags",
	},
	# FIXED: was resource_abuse (3); reassigning a VM's SA to a higher-privileged
	# one is a direct privilege escalation path → severity 4.
	"compute.instances.setServiceAccount": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set VM Service Account",
	},
	"compute.disks.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Disk",
	},
	"compute.disks.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Disk",
	},
	# NOTE: snapshot → share with attacker-controlled project → mount is a
	# known exfiltration chain. Kept at resource_abuse (3) here; the classifier
	# should apply a correlation rule if snapshot.insert is followed by
	# compute.snapshots.setIamPolicy to an external project.
	"compute.snapshots.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Snapshot",
	},
	"compute.firewalls.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Firewall Rule",
	},
	"compute.firewalls.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Firewall Rule",
	},
	"compute.networks.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create VPC Network",
	},
	"compute.subnetworks.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Subnetwork",
	},
	"compute.routes.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Route",
	},
	"compute.routers.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Cloud Router",
	},

	# GKE
	"container.clusters.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create GKE Cluster",
	},
	"container.clusters.update": {
		"category": "resource_abuse", "severity": 3,
		"label": "Update GKE Cluster",
	},
	"container.clusters.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete GKE Cluster",
	},
	"container.nodePools.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Node Pool",
	},
	"container.nodePools.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Node Pool",
	},

	# Pub/Sub
	"pubsub.topics.publish": {
		"category": "resource_abuse", "severity": 3,
		"label": "Publish Message",
	},
	"pubsub.topics.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Topic",
	},
	"pubsub.topics.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Topic",
	},
	"pubsub.subscriptions.create": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Subscription",
	},
	"pubsub.subscriptions.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Subscription",
	},

	# Cloud SQL
	"cloudsql.instances.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Cloud SQL Instance",
	},
	"cloudsql.instances.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Cloud SQL Instance",
	},
	"cloudsql.instances.restart": {
		"category": "resource_abuse", "severity": 3,
		"label": "Restart Cloud SQL Instance",
	},
	# ADDED: update can enable public IP or weaken SSL/TLS configuration
	"cloudsql.instances.update": {
		"category": "resource_abuse", "severity": 3,
		"label": "Update Cloud SQL Instance",
	},
	"cloudsql.users.insert": {
		"category": "resource_abuse", "severity": 3,
		"label": "Create Cloud SQL User",
	},
	"cloudsql.users.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Cloud SQL User",
	},

	# IAM — destructive but non-escalating
	# FIXED: was privilege_escalation (4); key deletion removes access rather
	# than granting it — this is defense evasion / resource destruction.
	"iam.serviceAccountKeys.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Service Account Key",
	},
	# FIXED: was privilege_escalation (4); role deletion removes permissions,
	# it does not grant them. Defense evasion / resource destruction.
	"iam.roles.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete IAM Role",
	},

	# KMS
	# FIXED: was privilege_escalation (4); encrypt does not expose data or
	# elevate access. Only decrypt belongs at severity 4 (see below).
	"cloudkms.cryptoKeys.encrypt": {
		"category": "resource_abuse", "severity": 3,
		"label": "Encrypt with KMS Key",
	},

	# =========================================================================
	# PRIVILEGE ESCALATION (Severity 4)
	# Credential creation/impersonation and permission changes.
	# =========================================================================

	# IAM
	"iam.serviceAccountKeys.create": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Create Service Account Key",
	},
	"iam.serviceAccounts.signJwt": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Sign JWT as Service Account",
	},
	"iam.serviceAccounts.signBlob": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Sign Blob as Service Account",
	},
	"iam.serviceAccounts.getAccessToken": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Mint Access Token",
	},
	"iam.serviceAccounts.getOpenIdToken": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Mint OIDC Token",
	},
	"iam.serviceAccounts.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set Service Account IAM Policy",
	},
	"iam.roles.create": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Create IAM Role",
	},
	"iam.roles.update": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Update IAM Role",
	},
	"cloudresourcemanager.projects.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set Project IAM Policy",
	},
	"cloudresourcemanager.folders.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set Folder IAM Policy",
	},
	"cloudresourcemanager.organizations.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set Organization IAM Policy",
	},

	# FIXED: replaced the non-existent "iam.serviceAccounts.implicitDelegation"
	# with the real audit log method. iam.serviceAccounts.actAs is the IAM
	# permission checked (and logged) when a principal attaches or impersonates
	# a service account, e.g. when deploying a VM/function/job with a SA.
	"iam.serviceAccounts.actAs": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Act As / Impersonate Service Account",
	},

	# Compute — FIXED from resource_abuse (3)
	# Reassigning a VM's service account to a higher-privileged one is a
	# direct and commonly exploited privilege escalation path.
	# (entry is kept in its original position above for readability, placed here
	# as a cross-reference note only — do not duplicate the key)

	# Cloud Functions — FIXED from resource_abuse (3)
	# Deploying or updating a function that runs as a privileged SA lets an
	# attacker execute arbitrary code with that SA's permissions.
	"cloudfunctions.functions.create": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Create Cloud Function",
	},
	"cloudfunctions.functions.update": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Update Cloud Function",
	},
	"cloudfunctions.functions.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Cloud Function",
	},

	# Cloud Run — FIXED from resource_abuse (3)
	# Deploying or updating a Cloud Run service that runs as a privileged SA
	# enables the same privesc pattern as Cloud Functions above.
	"run.services.create": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Create Cloud Run Service",
	},
	"run.services.update": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Update Cloud Run Service",
	},
	"run.services.delete": {
		"category": "resource_abuse", "severity": 3,
		"label": "Delete Cloud Run Service",
	},

	# KMS — decrypt only stays at severity 4
	"cloudkms.cryptoKeys.decrypt": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Decrypt with KMS Key",
	},
	"cloudkms.cryptoKeys.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set KMS Key IAM Policy",
	},

	# ADDED: Org policy weakening — removing/relaxing constraints (e.g. allowing
	# public IPs, disabling domain-restricted sharing) opens paths for exfil.
	"orgpolicy.policies.create": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Create Organization Policy",
	},
	"orgpolicy.policies.update": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Update Organization Policy",
	},
	"orgpolicy.policies.delete": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Delete Organization Policy",
	},

	# ADDED: BigQuery IAM — grants data access to external or unauthorized principals
	"bigquery.datasets.setIamPolicy": {
		"category": "privilege_escalation", "severity": 4,
		"label": "Set BigQuery Dataset IAM Policy",
	},

	# =========================================================================
	# EXFILTRATION (Severity 4)
	# High-sensitivity reads, export-style operations, and access grants that
	# directly expose data outside the trust boundary.
	# =========================================================================

	# Secret Manager
	"secretmanager.versions.access": {
		"category": "exfiltration", "severity": 4,
		"label": "Access Secret Version",
	},

	# BigQuery export / job creation
	# NOTE: bigquery.jobs.create covers ALL job types (QUERY, LOAD, EXTRACT,
	# COPY). EXTRACT jobs are the true exfil vector. Expect false-positive
	# volume on legitimate queries. Downstream classifier should filter on
	# jobType == "EXTRACT" where Cloud Audit Log proto detail is available.
	"bigquery.jobs.create": {
		"category": "exfiltration", "severity": 4,
		"label": "Create BigQuery Job (Export/Query)",
	},

	# Cloud Storage cross-bucket copy (commonly used to stage data in attacker-
	# controlled bucket before exfiltration)
	"storage.objects.rewrite": {
		"category": "exfiltration", "severity": 4,
		"label": "Rewrite Object (Cross-Bucket Copy)",
	},

	# ADDED: Making a bucket public bypasses all object-level ACLs instantly.
	# One call can expose an entire bucket to the public internet.
	"storage.buckets.setIamPolicy": {
		"category": "exfiltration", "severity": 4,
		"label": "Set Bucket IAM Policy (Potential Public Exposure)",
	},

	# ADDED: Direct database export to GCS — full DB dump without query-level
	# audit trail. Highly reliable exfiltration primitive.
	"cloudsql.instances.export": {
		"category": "exfiltration", "severity": 4,
		"label": "Export Cloud SQL Instance to GCS",
	},
}


def validate_taxonomy(taxonomy: dict[str, dict] | None = None) -> list[str]:
	taxonomy = taxonomy or GCP_API_TAXONOMY
	errors: list[str] = []
	for key, entry in taxonomy.items():
		if not isinstance(key, str) or not key:
			errors.append(f"Invalid key: {key!r}")
			continue
		if not isinstance(entry, dict):
			errors.append(f"Entry for {key} must be dict")
			continue
		category = entry.get("category")
		severity = entry.get("severity")
		label = entry.get("label")
		if category not in VALID_CATEGORIES:
			errors.append(f"{key}: invalid category {category!r}")
		if severity not in VALID_SEVERITIES:
			errors.append(f"{key}: invalid severity {severity!r}")
		if not isinstance(label, str) or not label.strip():
			errors.append(f"{key}: invalid label")
	return errors


def get_stats(taxonomy: dict[str, dict] | None = None) -> dict[str, object]:
	taxonomy = taxonomy or GCP_API_TAXONOMY
	category_counts: dict[str, int] = {}
	severity_counts: dict[int, int] = {}
	for entry in taxonomy.values():
		category = entry.get("category")
		severity = entry.get("severity")
		if isinstance(category, str):
			category_counts[category] = category_counts.get(category, 0) + 1
		if isinstance(severity, int):
			severity_counts[severity] = severity_counts.get(severity, 0) + 1
	return {
		"total": len(taxonomy),
		"category_counts": dict(sorted(category_counts.items())),
		"severity_counts": dict(sorted(severity_counts.items())),
	}


if __name__ == "__main__":
	errs = validate_taxonomy()
	if errs:
		print("Taxonomy validation failed:")
		for e in errs:
			print(f" - {e}")
		raise SystemExit(1)

	print("Taxonomy validation passed.")
	stats = get_stats()
	print(f"Total mappings: {stats['total']}")
	print(f"Category counts: {stats['category_counts']}")
	print(f"Severity counts: {stats['severity_counts']}")