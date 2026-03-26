# AWS API action → impact category mapping
# 7 categories as defined in the BreachTrace taxonomy
# TODO (Shashank/Day 1): complete mapping for 50+ actions.

RECONNAISSANCE = "reconnaissance"
DATA_ACCESS = "data_access"
DATA_EXFILTRATION = "data_exfiltration"
RESOURCE_ABUSE = "resource_abuse"
PRIVILEGE_ESCALATION = "privilege_escalation"
FINANCIAL_ABUSE = "financial_abuse"
CODE_COMPROMISE = "code_compromise"

# Severity weights per category
SEVERITY_WEIGHTS: dict[str, int] = {
    RECONNAISSANCE: 1,
    DATA_ACCESS: 2,
    RESOURCE_ABUSE: 3,
    FINANCIAL_ABUSE: 3,
    DATA_EXFILTRATION: 4,
    PRIVILEGE_ESCALATION: 4,
    CODE_COMPROMISE: 4,
}

# AWS action → impact category
AWS_ACTION_TAXONOMY: dict[str, str] = {
    # Reconnaissance
    "ListBuckets": RECONNAISSANCE,
    "ListObjects": RECONNAISSANCE,
    "ListObjectsV2": RECONNAISSANCE,
    "DescribeInstances": RECONNAISSANCE,
    "DescribeRegions": RECONNAISSANCE,
    "ListUsers": RECONNAISSANCE,
    "ListRoles": RECONNAISSANCE,
    "ListPolicies": RECONNAISSANCE,
    "GetCallerIdentity": RECONNAISSANCE,
    "DescribeSecurityGroups": RECONNAISSANCE,
    "DescribeVpcs": RECONNAISSANCE,
    "ListFunctions": RECONNAISSANCE,
    # Data Access
    "GetObject": DATA_ACCESS,
    "GetItem": DATA_ACCESS,
    "Query": DATA_ACCESS,
    "Scan": DATA_ACCESS,
    "GetSecretValue": DATA_ACCESS,
    "GetParameter": DATA_ACCESS,
    "GetParameters": DATA_ACCESS,
    # Resource Abuse
    "RunInstances": RESOURCE_ABUSE,
    "CreateCluster": RESOURCE_ABUSE,
    "CreateFunction": RESOURCE_ABUSE,
    "InvokeFunction": RESOURCE_ABUSE,
    "CreateBucket": RESOURCE_ABUSE,
    "PutObject": RESOURCE_ABUSE,
    # Privilege Escalation
    "CreateAccessKey": PRIVILEGE_ESCALATION,
    "AttachUserPolicy": PRIVILEGE_ESCALATION,
    "AttachRolePolicy": PRIVILEGE_ESCALATION,
    "PutUserPolicy": PRIVILEGE_ESCALATION,
    "CreateUser": PRIVILEGE_ESCALATION,
    "AddUserToGroup": PRIVILEGE_ESCALATION,
    "UpdateAssumeRolePolicy": PRIVILEGE_ESCALATION,
    # Code Compromise
    "UpdateFunctionCode": CODE_COMPROMISE,
    "CreateRepository": CODE_COMPROMISE,
}
