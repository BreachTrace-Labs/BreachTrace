# STUB — Shashank implements this (Day 1-2, Task 1.4)
#
# Fill GCP_API_TAXONOMY with 80+ GCP API method mappings.
#
# Key format  : "service.resource.action"  (dot-separated, all lowercase)
#               e.g. "storage.objects.get", "iam.serviceAccountKeys.create"
#
# Value format:
#   {
#       "category": str,   # one of the constants below
#       "severity": int,   # 1=Low  2=Medium  3=High  4=Critical
#       "label":    str,   # human-readable  e.g. "Download Object"
#   }
#
# Categories (must match exactly — classifier/rules.py uses these strings):
#   "reconnaissance"      severity 1
#   "data_access"         severity 2-3
#   "exfiltration"        severity 4  (bulk escalation sets this automatically — no need to add here)
#   "resource_abuse"      severity 3
#   "privilege_escalation" severity 4
#
# Heuristic fallback (Shashank implements in rules.py) covers unknown actions
# by inspecting the last dot-segment:
#   list / get / create / delete / update / setIamPolicy / signJwt
# — so only add explicit entries where the heuristic would give the WRONG result.
#
# Required entries for tests to pass (see tests/test_gcp_classifier.py):
#   "storage.objects.get"          → data_access,          severity 2
#   "iam.serviceAccountKeys.create"→ privilege_escalation,  severity 4  ← heuristic gives resource_abuse — needs override
#   "compute.instances.insert"     → resource_abuse,        severity 3  ← heuristic has no "insert" rule
#   "bigquery.tables.getData"      → data_access,           severity 2  ← needed for bulk escalation test

GCP_API_TAXONOMY: dict[str, dict] = {}
