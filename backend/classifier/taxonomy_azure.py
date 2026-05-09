# STUB — Shashank implements this (Day 2-3, Task 2.7)
#
# Fill AZURE_API_TAXONOMY with 70+ Azure operation mappings.
#
# Key format  : "Microsoft.Service/resource/action"  (exact operation name, mixed case)
#               e.g. "Microsoft.Storage/storageAccounts/read"
#                    "Microsoft.Authorization/roleAssignments/write"
#
# Value format:
#   {
#       "category": str,   # one of the constants below
#       "severity": int,   # 1=Low  2=Medium  3=High  4=Critical
#       "label":    str,   # human-readable  e.g. "Read Storage Account"
#   }
#
# Categories (must match exactly — classifier/rules.py uses these strings):
#   "reconnaissance"       severity 1
#   "data_access"          severity 2-3
#   "exfiltration"         severity 4  (bulk escalation sets this automatically)
#   "resource_abuse"       severity 3
#   "privilege_escalation" severity 4
#
# Heuristic fallback (Shashank implements in rules.py) covers unknown actions
# by inspecting the operation suffix:
#   /read   → reconnaissance  1
#   /write  → resource_abuse  3
#   /delete → resource_abuse  3
#   /action → resource_abuse  3
# Special privilege escalation patterns (override /write heuristic):
#   roleAssignments/write, roleDefinitions/write, policies/write → privilege_escalation 4
#
# Required entries for tests to pass (see tests/test_azure_classifier.py):
#   "Microsoft.Storage/storageAccounts/read"          → reconnaissance,      severity 1  (heuristic covers this)
#   "Microsoft.Authorization/roleAssignments/write"   → privilege_escalation, severity 4  (heuristic covers via special pattern)
#   "Microsoft.Compute/virtualMachines/write"         → resource_abuse,       severity 3  (heuristic covers this)
#   "Microsoft.KeyVault/vaults/secrets/read"          → data_access,          severity 2  ← heuristic gives reconnaissance — needs explicit entry for bulk test

AZURE_API_TAXONOMY: dict[str, dict] = {}
