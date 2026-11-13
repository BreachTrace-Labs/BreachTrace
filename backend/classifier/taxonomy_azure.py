"""
Azure Activity Log API taxonomy.

Format: "Microsoft.Service/resource/action" → {category, severity, label}

Categories:
  reconnaissance       — read, list, get operations
  data_access          — reading secrets, keys, sensitive data blobs
  exfiltration         — copying/exporting data outside subscription
  resource_abuse       — creating/modifying compute or storage resources
  privilege_escalation — RBAC, role assignments, policy changes
  financial_abuse      — budget / cost management abuse
  communication_abuse  — Service Bus, Event Hub messaging abuse
  code_compromise      — deploying code (Functions, Container Apps, etc.)

Severity scale: 1=Low 2=Medium 3=High 4=Critical
"""
from __future__ import annotations

AZURE_API_TAXONOMY: dict[str, dict] = {
    # ------------------------------------------------------------------ #
    # Azure Key Vault                                                      #
    # ------------------------------------------------------------------ #
    "Microsoft.KeyVault/vaults/secrets/read": {
        "category": "data_access",
        "severity": 2,
        "label": "Read Secret",
    },
    "Microsoft.KeyVault/vaults/secrets/write": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Write Secret",
    },
    "Microsoft.KeyVault/vaults/secrets/delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Secret",
    },
    "Microsoft.KeyVault/vaults/keys/read": {
        "category": "data_access",
        "severity": 3,
        "label": "Read Encryption Key",
    },
    "Microsoft.KeyVault/vaults/keys/write": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Write Encryption Key",
    },
    "Microsoft.KeyVault/vaults/keys/delete": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Delete Encryption Key",
    },
    "Microsoft.KeyVault/vaults/certificates/read": {
        "category": "data_access",
        "severity": 2,
        "label": "Read Certificate",
    },
    "Microsoft.KeyVault/vaults/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read Key Vault Metadata",
    },
    "Microsoft.KeyVault/vaults/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update Key Vault",
    },
    "Microsoft.KeyVault/vaults/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Key Vault",
    },
    "Microsoft.KeyVault/vaults/accessPolicies/write": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Modify Key Vault Access Policy",
    },

    # ------------------------------------------------------------------ #
    # Azure Storage                                                        #
    # ------------------------------------------------------------------ #
    "Microsoft.Storage/storageAccounts/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read Storage Account",
    },
    "Microsoft.Storage/storageAccounts/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update Storage Account",
    },
    "Microsoft.Storage/storageAccounts/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Storage Account",
    },
    "Microsoft.Storage/storageAccounts/listKeys/action": {
        "category": "data_access",
        "severity": 4,
        "label": "List Storage Account Keys",
    },
    "Microsoft.Storage/storageAccounts/regenerateKey/action": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Regenerate Storage Keys",
    },
    "Microsoft.Storage/storageAccounts/blobServices/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read Blob Service",
    },
    "Microsoft.Storage/storageAccounts/blobServices/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Configure Blob Service",
    },
    "Microsoft.Storage/storageAccounts/fileServices/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read File Service",
    },

    # ------------------------------------------------------------------ #
    # Azure IAM / Authorization (RBAC)                                    #
    # ------------------------------------------------------------------ #
    "Microsoft.Authorization/roleAssignments/write": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Assign RBAC Role",
    },
    "Microsoft.Authorization/roleAssignments/delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete RBAC Role Assignment",
    },
    "Microsoft.Authorization/roleAssignments/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read Role Assignments",
    },
    "Microsoft.Authorization/roleDefinitions/write": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Create/Update Role Definition",
    },
    "Microsoft.Authorization/roleDefinitions/delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Role Definition",
    },
    "Microsoft.Authorization/policyAssignments/write": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Assign Azure Policy",
    },
    "Microsoft.Authorization/policyAssignments/delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Policy Assignment",
    },
    "Microsoft.Authorization/elevateAccess/action": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Elevate Access to All Subscriptions",
    },

    # ------------------------------------------------------------------ #
    # Azure Active Directory / Entra ID (via Microsoft.Graph)             #
    # ------------------------------------------------------------------ #
    "Microsoft.AAD/register/action": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Register AAD Application",
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/write": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Create Managed Identity",
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/delete": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Delete Managed Identity",
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Assign Managed Identity",
    },

    # ------------------------------------------------------------------ #
    # Azure Compute                                                        #
    # ------------------------------------------------------------------ #
    "Microsoft.Compute/virtualMachines/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/start/action": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Start Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/deallocate/action": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Deallocate Virtual Machine",
    },
    "Microsoft.Compute/virtualMachines/extensions/write": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Install VM Extension (code injection)",
    },
    "Microsoft.Compute/virtualMachineScaleSets/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update VM Scale Set",
    },
    "Microsoft.Compute/disks/write": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create/Update Managed Disk",
    },
    "Microsoft.Compute/disks/delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Managed Disk",
    },
    "Microsoft.Compute/snapshots/write": {
        "category": "exfiltration",
        "severity": 3,
        "label": "Create Disk Snapshot",
    },

    # ------------------------------------------------------------------ #
    # Azure Networking                                                     #
    # ------------------------------------------------------------------ #
    "Microsoft.Network/networkSecurityGroups/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update NSG",
    },
    "Microsoft.Network/networkSecurityGroups/delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete NSG",
    },
    "Microsoft.Network/networkSecurityGroups/securityRules/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Modify NSG Security Rule",
    },
    "Microsoft.Network/virtualNetworks/write": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create/Update Virtual Network",
    },
    "Microsoft.Network/virtualNetworks/delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete Virtual Network",
    },
    "Microsoft.Network/publicIPAddresses/write": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create/Update Public IP",
    },

    # ------------------------------------------------------------------ #
    # Azure SQL / Database                                                 #
    # ------------------------------------------------------------------ #
    "Microsoft.Sql/servers/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read SQL Server",
    },
    "Microsoft.Sql/servers/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update SQL Server",
    },
    "Microsoft.Sql/servers/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete SQL Server",
    },
    "Microsoft.Sql/servers/databases/read": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Read SQL Database",
    },
    "Microsoft.Sql/servers/databases/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update SQL Database",
    },
    "Microsoft.Sql/servers/databases/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete SQL Database",
    },
    "Microsoft.Sql/servers/firewallRules/write": {
        "category": "privilege_escalation",
        "severity": 3,
        "label": "Modify SQL Firewall Rules",
    },
    "Microsoft.Sql/servers/administrators/write": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Set SQL AAD Admin",
    },

    # ------------------------------------------------------------------ #
    # Azure Functions / App Service (code deployment)                     #
    # ------------------------------------------------------------------ #
    "Microsoft.Web/sites/write": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Create/Update App Service / Function App",
    },
    "Microsoft.Web/sites/delete": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Delete App Service",
    },
    "Microsoft.Web/sites/config/write": {
        "category": "code_compromise",
        "severity": 4,
        "label": "Update App Service Config (env vars / secrets)",
    },
    "Microsoft.Web/sites/publishxml/action": {
        "category": "code_compromise",
        "severity": 3,
        "label": "Get App Service Publish Credentials",
    },

    # ------------------------------------------------------------------ #
    # Azure Container / AKS                                               #
    # ------------------------------------------------------------------ #
    "Microsoft.ContainerService/managedClusters/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Create/Update AKS Cluster",
    },
    "Microsoft.ContainerService/managedClusters/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete AKS Cluster",
    },
    "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action": {
        "category": "privilege_escalation",
        "severity": 4,
        "label": "Get AKS Admin Credentials",
    },
    "Microsoft.ContainerRegistry/registries/write": {
        "category": "code_compromise",
        "severity": 3,
        "label": "Create/Update Container Registry",
    },
    "Microsoft.ContainerRegistry/registries/listCredentials/action": {
        "category": "data_access",
        "severity": 4,
        "label": "List Container Registry Credentials",
    },

    # ------------------------------------------------------------------ #
    # Azure Service Bus / Event Hub (messaging)                           #
    # ------------------------------------------------------------------ #
    "Microsoft.ServiceBus/namespaces/write": {
        "category": "communication_abuse",
        "severity": 2,
        "label": "Create/Update Service Bus Namespace",
    },
    "Microsoft.ServiceBus/namespaces/authorizationRules/write": {
        "category": "communication_abuse",
        "severity": 3,
        "label": "Modify Service Bus Auth Rules",
    },
    "Microsoft.EventHub/namespaces/write": {
        "category": "communication_abuse",
        "severity": 2,
        "label": "Create/Update Event Hub Namespace",
    },

    # ------------------------------------------------------------------ #
    # Azure Cost Management / Billing                                     #
    # ------------------------------------------------------------------ #
    "Microsoft.CostManagement/budgets/write": {
        "category": "financial_abuse",
        "severity": 3,
        "label": "Create/Update Budget",
    },
    "Microsoft.CostManagement/budgets/delete": {
        "category": "financial_abuse",
        "severity": 3,
        "label": "Delete Budget",
    },
    # Budgets are logged by ARM under the Consumption provider.
    "Microsoft.Consumption/budgets/write": {
        "category": "financial_abuse",
        "severity": 3,
        "label": "Create/Update Budget",
    },
    "Microsoft.Consumption/budgets/delete": {
        "category": "financial_abuse",
        "severity": 3,
        "label": "Delete Budget",
    },
    "Microsoft.Billing/billingAccounts/write": {
        "category": "financial_abuse",
        "severity": 4,
        "label": "Modify Billing Account",
    },

    # ------------------------------------------------------------------ #
    # Azure Monitor / Diagnostics                                         #
    # ------------------------------------------------------------------ #
    "Microsoft.Insights/diagnosticSettings/write": {
        "category": "exfiltration",
        "severity": 3,
        "label": "Create Log Export (exfil route)",
    },
    "Microsoft.Insights/diagnosticSettings/delete": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Delete Diagnostic Setting",
    },
    "Microsoft.Insights/alertRules/write": {
        "category": "reconnaissance",
        "severity": 1,
        "label": "Create Alert Rule",
    },
    "Microsoft.Insights/alertRules/delete": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Delete Alert Rule",
    },

    # ------------------------------------------------------------------ #
    # Azure Resource Manager                                              #
    # ------------------------------------------------------------------ #
    "Microsoft.Resources/subscriptions/resourceGroups/write": {
        "category": "resource_abuse",
        "severity": 2,
        "label": "Create/Update Resource Group",
    },
    "Microsoft.Resources/subscriptions/resourceGroups/delete": {
        "category": "resource_abuse",
        "severity": 4,
        "label": "Delete Resource Group",
    },
    "Microsoft.Resources/deployments/write": {
        "category": "resource_abuse",
        "severity": 3,
        "label": "Deploy ARM Template",
    },
}

