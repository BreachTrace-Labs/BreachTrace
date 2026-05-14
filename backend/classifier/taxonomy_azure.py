"""Azure operation taxonomy.

Keys follow Azure Activity Log operation naming conventions (operationName.value),
typically in the form:

  "Microsoft.Provider/resourceType/.../read|write|delete|action"

For example, Microsoft Learn's Activity Log schema docs show operationName values
like "Microsoft.Network/networkSecurityGroups/write" and
"Microsoft.Storage/storageAccounts/listAccountSas/action".

IMPORTANT — LOG SOURCE SCOPE
=============================
Azure Activity Log captures CONTROL-PLANE (ARM) operations only.
Data-plane operations (blob reads, queue peeks, Key Vault secret fetches, etc.)
are NOT present in Activity Log — they appear in per-resource Diagnostic Logs
with a completely different schema (e.g. Key Vault audit logs use operation names
like "SecretGet", not ARM-style paths).

Operations in the DATA_PLANE_OPERATIONS dict below will NEVER appear in an ARM
Activity Log stream. The ingestion pipeline should also processes
resource-level Diagnostic Logs, and handle them with a separate schema parser.

Categories (must match exactly — classifier/rules.py uses these strings):
  - reconnaissance      (severity 1)   Discovery / listing; no data read
  - data_access         (severity 2-3) Reads implying access to customer data
  - resource_abuse      (severity 3)   Create/update/delete and operational mutations
  - privilege_escalation (severity 4)  Credential retrieval or permission changes
  - exfiltration        (severity 4)   Bulk export or high-sensitivity data reads
  - defense_evasion     (severity 4)   Disabling/destroying monitoring or security controls
"""

# =============================================================================
# CONTROL-PLANE OPERATIONS (ARM / Azure Activity Log)
# =============================================================================
AZURE_API_TAXONOMY: dict[str, dict] = {

    # =========================================================================
    # RECONNAISSANCE (Severity 1)
    # Low-impact discovery / listing; no data is read, only metadata.
    # =========================================================================

    # Storage — account/service/container metadata only (not blob contents)
    "Microsoft.Storage/storageAccounts/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Storage Account",
    },
    "Microsoft.Storage/storageAccounts/blobServices/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Blob Service",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Blob Containers",
    },
    "Microsoft.Storage/storageAccounts/fileServices/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read File Service",
    },
    "Microsoft.Storage/storageAccounts/fileServices/shares/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read File Shares",
    },
    "Microsoft.Storage/storageAccounts/queueServices/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Queue Service",
    },
    "Microsoft.Storage/storageAccounts/tableServices/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Table Service",
    },

    # Key Vault — metadata only; secret/key material is NOT returned by these
    "Microsoft.KeyVault/vaults/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Key Vault",
    },
    "Microsoft.KeyVault/vaults/accessPolicies/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Vault Access Policies",
    },
    "Microsoft.KeyVault/vaults/keys/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Vault Keys Metadata",
    },
    "Microsoft.KeyVault/vaults/certificates/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Certificates Metadata",
    },

    # IAM / Authorization — read-only; no permission changes
    "Microsoft.Authorization/roleAssignments/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Role Assignments",
    },
    "Microsoft.Authorization/roleDefinitions/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Role Definitions",
    },
    # FIX: was "policies/read" — correct ARM resource type is policyDefinitions
    "Microsoft.Authorization/policyDefinitions/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Policy Definitions",
    },
    "Microsoft.Authorization/policyAssignments/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Policy Assignments",
    },
    "Microsoft.Authorization/locks/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Resource Locks",
    },

    # Resource Manager
    "Microsoft.Resources/subscriptions/resourceGroups/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Resource Groups",
    },
    "Microsoft.Resources/deployments/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Deployments",
    },
    "Microsoft.ResourceGraph/resources/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Resource Graph Read",
    },

    # Compute
    "Microsoft.Compute/virtualMachines/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Virtual Machine",
    },
    "Microsoft.Compute/virtualMachineScaleSets/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read VM Scale Set",
    },
    "Microsoft.Compute/disks/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Managed Disk",
    },
    "Microsoft.Compute/snapshots/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Snapshot",
    },
    "Microsoft.Compute/images/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Compute Image",
    },

    # Network
    # FIX: was "Microsoft.Network/subnets/read" — subnets are a sub-resource of VNets
    "Microsoft.Network/virtualNetworks/subnets/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Subnet",
    },
    "Microsoft.Network/virtualNetworks/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Virtual Network",
    },
    "Microsoft.Network/networkSecurityGroups/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Network Security Group",
    },
    "Microsoft.Network/networkSecurityGroups/securityRules/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read NSG Security Rules",
    },
    "Microsoft.Network/publicIPAddresses/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Public IP",
    },
    "Microsoft.Network/loadBalancers/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Load Balancer",
    },
    "Microsoft.Network/applicationGateways/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Application Gateway",
    },
    "Microsoft.Network/routeTables/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Route Table",
    },
    "Microsoft.Network/privateDnsZones/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Private DNS Zone",
    },
    "Microsoft.Network/privateEndpoints/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Private Endpoint",
    },

    # SQL
    "Microsoft.Sql/servers/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read SQL Server",
    },
    "Microsoft.Sql/servers/databases/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read SQL Database",
    },
    "Microsoft.Sql/servers/firewallRules/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read SQL Firewall Rules",
    },

    # Container (AKS)
    "Microsoft.ContainerService/managedClusters/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read AKS Cluster",
    },
    "Microsoft.ContainerService/managedClusters/agentPools/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read AKS Agent Pools",
    },

    # App Service
    "Microsoft.Web/sites/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read App Service",
    },
    "Microsoft.Web/sites/config/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read App Service Config",
    },

    # Logic Apps
    "Microsoft.Logic/workflows/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Logic App Workflow",
    },

    # Monitor / Insights
    "Microsoft.Insights/metricDefinitions/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Metric Definitions",
    },
    "Microsoft.Insights/diagnosticSettings/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Diagnostic Settings",
    },
    "Microsoft.OperationalInsights/workspaces/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Log Analytics Workspace",
    },

    # Cosmos DB — metadata / schema only
    "Microsoft.DocumentDB/databaseAccounts/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Cosmos DB Account",
    },
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Cosmos SQL Databases",
    },
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Cosmos Containers",
    },
    # FIX: was "exfiltration" severity 4 — readThroughput reads the provisioned RU/s
    # setting, not document data; it is pure metadata reconnaissance.
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/throughputSettings/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Cosmos Container Throughput Setting",
    },

    # Security / Defender
    "Microsoft.Security/assessments/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Security Assessments",
    },
    "Microsoft.Security/pricings/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Defender Plans",
    },

    # Automation
    "Microsoft.Automation/automationAccounts/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Automation Account",
    },
    "Microsoft.Automation/automationAccounts/runbooks/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read Runbook",
    },

    # Managed Identity
    "Microsoft.ManagedIdentity/userAssignedIdentities/read": {
        "category": "reconnaissance", "severity": 1,
        "label": "Read User-Assigned Managed Identity",
    },

    # =========================================================================
    # DATA ACCESS (Severity 2-3)
    # Control-plane operations that return or imply access to customer data or
    # secret metadata (but not the secret material itself).
    # =========================================================================

    # Storage blob read (project reference)
    # Note: This string is commonly used as an Azure RBAC *dataAction* permission.
    # It typically won't appear in Azure Activity Log (ARM). Keep it here anyway
    # because BreachTrace uses `api_action` strings directly in experiments/tests.
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Blob",
    },

    # Key Vault — list operations return names/versions but not secret values;
    # elevated vs read because enumeration enables targeted exfiltration.
    "Microsoft.KeyVault/vaults/secrets/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Secret Names (Key Vault)",
    },
    "Microsoft.KeyVault/vaults/keys/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Key Names (Key Vault)",
    },
    "Microsoft.KeyVault/vaults/certificates/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Certificate Names (Key Vault)",
    },

    # SQL — settings that reveal backup/audit exposure surface
    "Microsoft.Sql/servers/databases/auditingSettings/read": {
        "category": "data_access", "severity": 2,
        "label": "Read DB Auditing Settings",
    },
    "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read": {
        "category": "data_access", "severity": 2,
        "label": "Read DB Backup Retention Policy",
    },

    # =========================================================================
    # PRIVILEGE ESCALATION (Severity 4)
    # Operations that grant, modify, or retrieve credentials / permissions.
    # =========================================================================

    # IAM — role assignment / definition mutations grant new permissions
    "Microsoft.Authorization/roleAssignments/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Role Assignment",
    },
    "Microsoft.Authorization/roleAssignments/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Role Assignment",
    },
    "Microsoft.Authorization/roleDefinitions/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Role Definition",
    },
    "Microsoft.Authorization/roleDefinitions/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Role Definition",
    },
    # FIX: was "policies/write|delete" — correct ARM type is policyDefinitions
    "Microsoft.Authorization/policyDefinitions/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Policy Definition",
    },
    # Compatibility alias (kept to match project reference docs/tests)
    "Microsoft.Authorization/policies/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Policy",
    },
    "Microsoft.Authorization/policyDefinitions/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Policy Definition",
    },
    "Microsoft.Authorization/policyAssignments/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Policy Assignment",
    },
    "Microsoft.Authorization/policyAssignments/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Policy Assignment",
    },

    # Storage — credential / SAS token retrieval
    "Microsoft.Storage/storageAccounts/listKeys/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Storage Account Keys",
    },
    "Microsoft.Storage/storageAccounts/regenerateKey/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Regenerate Storage Account Key",
    },
    "Microsoft.Storage/storageAccounts/listAccountSas/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Account SAS Token",
    },
    "Microsoft.Storage/storageAccounts/listServiceSas/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Service SAS Token",
    },

    # Key Vault — access policy changes modify who can access secrets
    "Microsoft.KeyVault/vaults/accessPolicies/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Vault Access Policy",
    },
    "Microsoft.KeyVault/vaults/accessPolicies/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Vault Access Policy",
    },

    # AKS — kubeconfig credential retrieval; admin credential is full cluster access
    "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Get AKS User Credentials",
    },
    "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Get AKS Admin Credentials",
    },

    # App Service — publishing profile and app settings contain secrets / deploy creds
    "Microsoft.Web/sites/publishxml/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Download App Service Publishing Profile",
    },
    "Microsoft.Web/sites/config/list/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List App Service App Settings (Secrets)",
    },
    # REMOVED: Microsoft.Web/sites/hostruntime/admin/instances/read
    # Not a real ARM Activity Log operation; internal Functions runtime path only.

    # Cosmos DB — key and connection string retrieval
    "Microsoft.DocumentDB/databaseAccounts/listKeys/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Cosmos DB Keys",
    },
    "Microsoft.DocumentDB/databaseAccounts/regenerateKey/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Regenerate Cosmos DB Key",
    },
    "Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Cosmos DB Connection Strings",
    },

    # Service Bus / Event Hubs — SAS key retrieval
    "Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Service Bus Keys",
    },
    "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action": {
        "category": "privilege_escalation", "severity": 4,
        "label": "List Event Hubs Keys",
    },

    # Managed Identity — federated credential abuse enables cross-tenant impersonation
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Write Federated Identity Credential",
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete": {
        "category": "privilege_escalation", "severity": 4,
        "label": "Delete Federated Identity Credential",
    },

    # =========================================================================
    # RESOURCE ABUSE (Severity 3)
    # Create / update / delete and operational mutations that do not directly
    # exfiltrate data or escalate permissions, but alter the environment.
    # =========================================================================

    # FIX: locks moved from privilege_escalation — a lock does not grant permissions.
    # write: prevents incident responders deleting resources (ransomware-like).
    # delete: precursor to destruction; not itself a privilege gain.
    "Microsoft.Authorization/locks/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Resource Lock (Blocks Deletion)",
    },
    "Microsoft.Authorization/locks/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Resource Lock (Enables Subsequent Destruction)",
    },

    # Compute
    "Microsoft.Compute/virtualMachines/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/start/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Start VM",
    },
    "Microsoft.Compute/virtualMachines/powerOff/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Power Off VM",
    },
    "Microsoft.Compute/virtualMachines/deallocate/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Deallocate VM",
    },
    "Microsoft.Compute/virtualMachines/redeploy/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Redeploy VM",
    },
    "Microsoft.Compute/virtualMachines/reimage/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Reimage VM",
    },
    # FIX: runCommand promoted to severity 4 — arbitrary code execution on the VM,
    # equivalent to interactive shell access; risk is fundamentally higher than other
    # resource mutations.
    "Microsoft.Compute/virtualMachines/runCommand/action": {
        "category": "resource_abuse", "severity": 4,
        "label": "Run VM Command (Arbitrary Code Execution)",
    },
    "Microsoft.Compute/virtualMachines/extensions/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write VM Extension",
    },
    # Added: removing security extensions (Defender, monitoring agents) is an evasion step
    "Microsoft.Compute/virtualMachines/extensions/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete VM Extension (Possible Security Agent Removal)",
    },
    "Microsoft.Compute/disks/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Managed Disk",
    },
    "Microsoft.Compute/disks/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Managed Disk",
    },
    "Microsoft.Compute/snapshots/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Snapshot",
    },
    "Microsoft.Compute/snapshots/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Snapshot",
    },

    # Network
    "Microsoft.Network/networkSecurityGroups/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Network Security Group",
    },
    "Microsoft.Network/networkSecurityGroups/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Network Security Group",
    },
    "Microsoft.Network/networkSecurityGroups/securityRules/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write NSG Rule",
    },
    "Microsoft.Network/networkSecurityGroups/securityRules/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete NSG Rule",
    },
    "Microsoft.Network/publicIPAddresses/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Public IP",
    },
    "Microsoft.Network/publicIPAddresses/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Public IP",
    },
    "Microsoft.Network/virtualNetworks/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Virtual Network",
    },
    "Microsoft.Network/virtualNetworks/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Virtual Network",
    },
    "Microsoft.Network/routeTables/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Route Table",
    },
    "Microsoft.Network/routeTables/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Route Table",
    },
    "Microsoft.Network/loadBalancers/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Load Balancer",
    },
    "Microsoft.Network/loadBalancers/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Load Balancer",
    },
    "Microsoft.Network/applicationGateways/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Application Gateway",
    },
    "Microsoft.Network/applicationGateways/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Application Gateway",
    },

    # Storage — container / account creation and deletion
    "Microsoft.Storage/storageAccounts/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Storage Account",
    },
    "Microsoft.Storage/storageAccounts/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Storage Account",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Blob Container",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Blob Container",
    },
    "Microsoft.Storage/storageAccounts/fileServices/shares/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write File Share",
    },
    "Microsoft.Storage/storageAccounts/fileServices/shares/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete File Share",
    },

    # Key Vault — vault and secret/key/cert creation and deletion
    "Microsoft.KeyVault/vaults/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Key Vault",
    },
    "Microsoft.KeyVault/vaults/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Key Vault",
    },
    "Microsoft.KeyVault/vaults/secrets/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Secret (Key Vault)",
    },
    "Microsoft.KeyVault/vaults/secrets/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Secret (Key Vault)",
    },
    "Microsoft.KeyVault/vaults/keys/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Key (Key Vault)",
    },
    "Microsoft.KeyVault/vaults/keys/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Key (Key Vault)",
    },

    # SQL
    "Microsoft.Sql/servers/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write SQL Server",
    },
    "Microsoft.Sql/servers/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete SQL Server",
    },
    "Microsoft.Sql/servers/databases/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write SQL Database",
    },
    "Microsoft.Sql/servers/databases/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete SQL Database",
    },
    "Microsoft.Sql/servers/firewallRules/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write SQL Firewall Rule",
    },
    "Microsoft.Sql/servers/firewallRules/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete SQL Firewall Rule",
    },

    # AKS
    "Microsoft.ContainerService/managedClusters/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write AKS Cluster",
    },
    "Microsoft.ContainerService/managedClusters/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete AKS Cluster",
    },
    "Microsoft.ContainerService/managedClusters/agentPools/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write AKS Agent Pool",
    },
    "Microsoft.ContainerService/managedClusters/agentPools/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete AKS Agent Pool",
    },

    # App Service
    "Microsoft.Web/sites/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write App Service",
    },
    "Microsoft.Web/sites/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete App Service",
    },
    "Microsoft.Web/sites/config/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write App Service Config",
    },
    "Microsoft.Web/sites/stop/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Stop App Service",
    },
    "Microsoft.Web/sites/start/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Start App Service",
    },

    # Logic Apps
    "Microsoft.Logic/workflows/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Logic App Workflow",
    },
    "Microsoft.Logic/workflows/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Logic App Workflow",
    },
    "Microsoft.Logic/workflows/run/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Run Logic App",
    },

    # Resources
    "Microsoft.Resources/subscriptions/resourceGroups/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Resource Group",
    },
    "Microsoft.Resources/subscriptions/resourceGroups/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Resource Group",
    },
    "Microsoft.Resources/deployments/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Deployment",
    },
    "Microsoft.Resources/deployments/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Deployment",
    },

    # Automation — runbook injection enables persistence / lateral movement
    "Microsoft.Automation/automationAccounts/runbooks/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Runbook (Possible Persistence)",
    },
    "Microsoft.Automation/automationAccounts/runbooks/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Runbook",
    },
    "Microsoft.Automation/automationAccounts/jobs/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Start Automation Job",
    },

    # =========================================================================
    # EXFILTRATION (Severity 4)
    # Operations that directly return bulk data or high-sensitivity secret material.
    # =========================================================================

    # Key Vault — treat as data_access so bulk escalation can upgrade to
    # exfiltration when the same source IP repeatedly reads secrets.
    "Microsoft.KeyVault/vaults/secrets/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Secret Value (Key Vault ARM)",
    },

    # SQL — export writes entire database to blob storage
    "Microsoft.Sql/servers/databases/export/action": {
        "category": "exfiltration", "severity": 4,
        "label": "Export SQL Database to Blob",
    },
    # FIX: import/action was incorrectly classified as exfiltration.
    # Import moves data INTO the database; it is resource_abuse, not exfiltration.
    # See resource_abuse section — "Microsoft.Sql/servers/databases/import/action" below.

    # FIX: snapshots/grantAccess moved from resource_abuse — this hands a time-limited
    # SAS URI for the full disk snapshot to an arbitrary principal, which is a direct
    # data exfiltration path equivalent to listKeys.
    "Microsoft.Compute/snapshots/grantAccess/action": {
        "category": "exfiltration", "severity": 4,
        "label": "Grant SAS Access to Disk Snapshot (Exfiltration Path)",
    },
    "Microsoft.Compute/disks/grantAccess/action": {
        "category": "exfiltration", "severity": 4,
        "label": "Grant SAS Access to Managed Disk (Exfiltration Path)",
    },

    # =========================================================================
    # SQL IMPORT — resource_abuse (data is written in, not out)
    # =========================================================================
    "Microsoft.Sql/servers/databases/import/action": {
        "category": "resource_abuse", "severity": 3,
        "label": "Import Data into SQL Database",
    },

    # =========================================================================
    # DEFENSE EVASION (Severity 4)
    # Destroying monitoring, audit trails, or security controls. These actions
    # reduce defender visibility and are high-priority indicators of an active
    # intrusion or cover-up attempt.
    # =========================================================================

    # Diagnostic settings delete — destroys the pipeline forwarding logs to SIEM
    "Microsoft.Insights/diagnosticSettings/delete": {
        "category": "defense_evasion", "severity": 4,
        "label": "Delete Diagnostic Settings (Audit Trail Destruction)",
    },
    "Microsoft.Insights/diagnosticSettings/write": {
        "category": "defense_evasion", "severity": 3,
        "label": "Write Diagnostic Settings (Possible Log Redirection)",
    },

    # Activity log alert deletion — removes alerting on suspicious operations
    "Microsoft.Insights/activityLogAlerts/delete": {
        "category": "defense_evasion", "severity": 4,
        "label": "Delete Activity Log Alert",
    },
    "Microsoft.Insights/activityLogAlerts/write": {
        "category": "defense_evasion", "severity": 3,
        "label": "Write Activity Log Alert (Possible Alert Suppression)",
    },

    # Log Analytics workspace deletion — wipes stored logs
    "Microsoft.OperationalInsights/workspaces/delete": {
        "category": "defense_evasion", "severity": 4,
        "label": "Delete Log Analytics Workspace (Log Wipe)",
    },

    # Defender for Cloud plan downgrade — disables threat detection
    "Microsoft.Security/pricings/write": {
        "category": "defense_evasion", "severity": 4,
        "label": "Write Defender Plan (Possible Downgrade/Disable)",
    },
}


# =============================================================================
# DATA-PLANE OPERATIONS
# These will NOT appear in Azure Activity Log. They are captured in per-resource
# Diagnostic Logs (e.g. Key Vault audit logs, Storage Analytics, SQL Audit).
# If your ingestion pipeline processes those sources, parse them separately —
# they use a different schema (resourceId + operationName not in ARM format).
#
# Included here for documentation / future use.
# =============================================================================
DATA_PLANE_OPERATIONS: dict[str, dict] = {
    # Storage blob data plane (Storage Analytics / resource diagnostic logs)
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Blob (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Blob Tags (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/versions/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Blob Version (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write": {
        "category": "resource_abuse", "severity": 3,
        "label": "Write Blob (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete": {
        "category": "resource_abuse", "severity": 3,
        "label": "Delete Blob (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/fileServices/shares/files/read": {
        "category": "data_access", "severity": 2,
        "label": "Read File (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/fileServices/shares/snapshots/read": {
        "category": "data_access", "severity": 2,
        "label": "Read File Share Snapshot (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/queueServices/queues/messages/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Queue Message (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read": {
        "category": "data_access", "severity": 2,
        "label": "Read Table Entity (Data Plane)",
        "log_source": "Storage Analytics / Diagnostic Logs",
    },
    # Key Vault data plane (Key Vault audit diagnostic logs)
    # Note: operation names in KV audit logs are "SecretGet", "KeySign", etc.,
    # NOT the ARM-style paths shown here. Map accordingly in your parser.
    "Microsoft.KeyVault/vaults/secrets/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Secrets (Data Plane)",
        "log_source": "Key Vault Audit Diagnostic Logs",
        "kv_operation_name": "SecretList",
    },
    "Microsoft.KeyVault/vaults/keys/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Keys (Data Plane)",
        "log_source": "Key Vault Audit Diagnostic Logs",
        "kv_operation_name": "KeyList",
    },
    "Microsoft.KeyVault/vaults/certificates/list/action": {
        "category": "data_access", "severity": 3,
        "label": "List Certificates (Data Plane)",
        "log_source": "Key Vault Audit Diagnostic Logs",
        "kv_operation_name": "CertificateList",
    },
}


# =============================================================================
# STATISTICS & VALIDATION
# =============================================================================

VALID_CATEGORIES = frozenset({
    "reconnaissance",
    "data_access",
    "resource_abuse",
    "privilege_escalation",
    "exfiltration",
    "defense_evasion",
})

VALID_SEVERITIES = frozenset({1, 2, 3, 4})


def get_stats(taxonomy: dict | None = None) -> dict:
    """Return category and severity breakdown for the given taxonomy dict.

    Defaults to AZURE_API_TAXONOMY (control-plane only).
    """
    if taxonomy is None:
        taxonomy = AZURE_API_TAXONOMY
    categories: dict[str, int] = {}
    severities: dict[int, int] = {}
    for _, data in taxonomy.items():
        cat = data["category"]
        sev = data["severity"]
        categories[cat] = categories.get(cat, 0) + 1
        severities[sev] = severities.get(sev, 0) + 1
    return {
        "total_operations": len(taxonomy),
        "categories": categories,
        "severities": severities,
    }


def validate_taxonomy(taxonomy: dict | None = None) -> list[str]:
    """Return a list of validation errors. Empty list means taxonomy is clean."""
    if taxonomy is None:
        taxonomy = AZURE_API_TAXONOMY
    errors: list[str] = []
    seen_keys: set[str] = set()
    for op, data in taxonomy.items():
        if op in seen_keys:
            errors.append(f"Duplicate operation key: {op}")
        seen_keys.add(op)
        if data.get("category") not in VALID_CATEGORIES:
            errors.append(f"Invalid category '{data.get('category')}' for {op}")
        if data.get("severity") not in VALID_SEVERITIES:
            errors.append(f"Invalid severity '{data.get('severity')}' for {op}")
        if not data.get("label"):
            errors.append(f"Missing label for {op}")
    return errors


if __name__ == "__main__":
    errors = validate_taxonomy()
    if errors:
        print("VALIDATION ERRORS:")
        for e in errors:
            print(f"  {e}")
    else:
        print("Taxonomy validation passed.")

    print()
    stats = get_stats()
    print(f"Total control-plane operations : {stats['total_operations']}")
    print(f"Category breakdown             : {stats['categories']}")
    print(f"Severity distribution          : {stats['severities']}")

    print()
    dp_stats = get_stats(DATA_PLANE_OPERATIONS)
    print(f"Data-plane operations (separate log source): {dp_stats['total_operations']}")