AWS_API_TAXONOMY = {
    # ================= RECONNAISSANCE (Severity 1-2) =================
    # Discovery and enumeration actions - low individual impact
    "sts:GetCallerIdentity": {"category": "reconnaissance", "severity": 1, "label": "Identity Probe"},
    "sts:GetAccessKeyInfo": {"category": "reconnaissance", "severity": 1, "label": "Access Key Info"},
    "sts:GetSessionToken": {"category": "reconnaissance", "severity": 2, "label": "Get Session Token"},

    # === IAM Reconnaissance ===
    "iam:GetUser": {"category": "reconnaissance", "severity": 1, "label": "Get User"},
    "iam:GetRole": {"category": "reconnaissance", "severity": 1, "label": "Get Role"},
    "iam:GetPolicy": {"category": "reconnaissance", "severity": 1, "label": "Get Policy"},
    "iam:GetAccountSummary": {"category": "reconnaissance", "severity": 1, "label": "Account Summary"},
    "iam:ListUsers": {"category": "reconnaissance", "severity": 1, "label": "List Users"},
    "iam:ListRoles": {"category": "reconnaissance", "severity": 1, "label": "List Roles"},
    "iam:ListPolicies": {"category": "reconnaissance", "severity": 1, "label": "List Policies"},
    "iam:ListGroups": {"category": "reconnaissance", "severity": 1, "label": "List Groups"},
    "iam:ListAccessKeys": {"category": "reconnaissance", "severity": 1, "label": "List Access Keys"},
    "iam:ListMFADevices": {"category": "reconnaissance", "severity": 1, "label": "List MFA Devices"},
    "iam:ListRoleTags": {"category": "reconnaissance", "severity": 1, "label": "List Role Tags"},
    "iam:ListUserTags": {"category": "reconnaissance", "severity": 1, "label": "List User Tags"},

    # More sensitive IAM reconnaissance
    "iam:ListPolicyVersions": {"category": "reconnaissance", "severity": 2, "label": "List Policy Versions"},
    "iam:GetUserPolicy": {"category": "reconnaissance", "severity": 2, "label": "Get User Policy"},
    "iam:GetRolePolicy": {"category": "reconnaissance", "severity": 2, "label": "Get Role Policy"},
    "iam:GetGroupPolicy": {"category": "reconnaissance", "severity": 2, "label": "Get Group Policy"},
    "iam:ListAttachedUserPolicies": {"category": "reconnaissance", "severity": 2, "label": "List Attached User Policies"},
    "iam:ListAttachedRolePolicies": {"category": "reconnaissance", "severity": 2, "label": "List Attached Role Policies"},

    # Credential exposure
    "iam:GetCredentialReport": {"category": "reconnaissance", "severity": 2, "label": "Credential Report"},
    "iam:GenerateCredentialReport": {"category": "reconnaissance", "severity": 2, "label": "Generate Credential Report"},
    "iam:GetLoginProfile": {"category": "reconnaissance", "severity": 2, "label": "Get Login Profile"},

    # === EC2 Reconnaissance ===
    "ec2:DescribeInstances": {"category": "reconnaissance", "severity": 1, "label": "Describe Instances"},
    "ec2:DescribeImages": {"category": "reconnaissance", "severity": 1, "label": "Describe Images"},
    "ec2:DescribeSecurityGroups": {"category": "reconnaissance", "severity": 1, "label": "Security Groups"},
    "ec2:DescribeSubnets": {"category": "reconnaissance", "severity": 1, "label": "Subnets"},
    "ec2:DescribeVpcs": {"category": "reconnaissance", "severity": 1, "label": "VPCs"},
    "ec2:DescribeVolumes": {"category": "reconnaissance", "severity": 1, "label": "Volumes"},
    "ec2:DescribeSnapshots": {"category": "reconnaissance", "severity": 1, "label": "Snapshots"},
    "ec2:DescribeTags": {"category": "reconnaissance", "severity": 1, "label": "Tags"},
    "ec2:DescribeInstanceStatus": {"category": "reconnaissance", "severity": 1, "label": "Instance Status"},
    "ec2:DescribeNetworkInterfaces": {"category": "reconnaissance", "severity": 1, "label": "Network Interfaces"},
    "ec2:DescribeKeyPairs": {"category": "reconnaissance", "severity": 1, "label": "Key Pairs"},

    # === S3 Reconnaissance ===
    "s3:ListBuckets": {"category": "reconnaissance", "severity": 1, "label": "List Buckets"},
    "s3:ListBucket": {"category": "reconnaissance", "severity": 1, "label": "List Objects"},
    "s3:GetBucketLocation": {"category": "reconnaissance", "severity": 1, "label": "Bucket Region"},
    "s3:GetBucketPolicy": {"category": "reconnaissance", "severity": 2, "label": "Bucket Policy"},
    "s3:GetBucketAcl": {"category": "reconnaissance", "severity": 2, "label": "Bucket ACL"},
    "s3:GetBucketEncryption": {"category": "reconnaissance", "severity": 1, "label": "Bucket Encryption"},
    "s3:GetBucketVersioning": {"category": "reconnaissance", "severity": 1, "label": "Bucket Versioning"},
    "s3:GetBucketTagging": {"category": "reconnaissance", "severity": 1, "label": "Bucket Tags"},

    # === Database & DataStore Reconnaissance ===
    "rds:DescribeDBInstances": {"category": "reconnaissance", "severity": 1, "label": "RDS Instances"},
    "rds:DescribeDBClusters": {"category": "reconnaissance", "severity": 1, "label": "RDS Clusters"},
    "dynamodb:ListTables": {"category": "reconnaissance", "severity": 1, "label": "List Tables"},
    "dynamodb:DescribeTable": {"category": "reconnaissance", "severity": 1, "label": "Describe Table"},
    "lambda:ListFunctions": {"category": "reconnaissance", "severity": 1, "label": "List Lambda"},
    "lambda:GetFunction": {"category": "reconnaissance", "severity": 2, "label": "Get Function Config"},
    "lambda:ListLayers": {"category": "reconnaissance", "severity": 1, "label": "List Layers"},

    # === Audit & Monitoring ===
    "cloudtrail:LookupEvents": {"category": "reconnaissance", "severity": 2, "label": "Audit Logs"},
    "cloudtrail:DescribeTrails": {"category": "reconnaissance", "severity": 1, "label": "Describe Trails"},
    "cloudwatch:ListMetrics": {"category": "reconnaissance", "severity": 1, "label": "List Metrics"},
    "cloudwatch:DescribeAlarms": {"category": "reconnaissance", "severity": 1, "label": "Alarms"},

    # === Container & Orchestration ===
    "ecs:ListClusters": {"category": "reconnaissance", "severity": 1, "label": "List ECS Clusters"},
    "ecs:DescribeClusters": {"category": "reconnaissance", "severity": 1, "label": "Describe Clusters"},
    "ecs:DescribeTasks": {"category": "reconnaissance", "severity": 1, "label": "Describe ECS Tasks"},
    "ecs:ListTaskDefinitions": {"category": "reconnaissance", "severity": 1, "label": "List Task Defs"},
    "ecs:DescribeTaskDefinition": {"category": "reconnaissance", "severity": 2, "label": "Task Def Details"},
    "eks:ListClusters": {"category": "reconnaissance", "severity": 1, "label": "List EKS Clusters"},
    "eks:DescribeCluster": {"category": "reconnaissance", "severity": 1, "label": "Describe EKS Cluster"},

    # === Load Balancing & Network ===
    "elasticloadbalancing:DescribeLoadBalancers": {"category": "reconnaissance", "severity": 1, "label": "Describe ELB"},
    "elasticloadbalancing:DescribeTargetGroups": {"category": "reconnaissance", "severity": 1, "label": "Describe Target Groups"},
    "elasticloadbalancing:DescribeListeners": {"category": "reconnaissance", "severity": 1, "label": "Listeners"},

    # === Container Registry ===
    "ecr:DescribeRepositories": {"category": "reconnaissance", "severity": 1, "label": "Describe ECR"},
    "ecr:ListImages": {"category": "reconnaissance", "severity": 1, "label": "List Images"},
    "ecr:DescribeImages": {"category": "reconnaissance", "severity": 1, "label": "Describe Images"},

    # === Logging ===
    "logs:DescribeLogGroups": {"category": "reconnaissance", "severity": 1, "label": "Log Groups"},
    "logs:DescribeLogStreams": {"category": "reconnaissance", "severity": 1, "label": "Log Streams"},
    "logs:ListTagsLogGroup": {"category": "reconnaissance", "severity": 1, "label": "Log Tags"},

    # === Analytics ===
    "athena:ListDatabases": {"category": "reconnaissance", "severity": 1, "label": "Athena DBs"},
    "athena:ListTableMetadata": {"category": "reconnaissance", "severity": 1, "label": "Athena Tables"},
    "athena:GetDatabase": {"category": "reconnaissance", "severity": 1, "label": "Get Database"},
    "glue:GetDatabases": {"category": "reconnaissance", "severity": 1, "label": "Glue Databases"},
    "glue:GetTables": {"category": "reconnaissance", "severity": 1, "label": "Glue Tables"},
    "glue:GetCatalogImportStatus": {"category": "reconnaissance", "severity": 1, "label": "Catalog Status"},
    "redshift:DescribeClusters": {"category": "reconnaissance", "severity": 1, "label": "Redshift Clusters"},

    # ================= DATA ACCESS (Severity 2-4) =================
    "s3:GetObject": {"category": "data_access", "severity": 3, "label": "Read Object"},
    "s3:GetObjectVersion": {"category": "data_access", "severity": 3, "label": "Read Object Version"},
    "s3:SelectObjectContent": {"category": "data_access", "severity": 3, "label": "Query Object"},
    "s3:GetObjectTagging": {"category": "data_access", "severity": 2, "label": "Object Tags"},

    "dynamodb:GetItem": {"category": "data_access", "severity": 3, "label": "Get Item"},
    "dynamodb:Query": {"category": "data_access", "severity": 3, "label": "Query Table"},
    "dynamodb:Scan": {"category": "data_access", "severity": 3, "label": "Scan Table"},

    # Secrets & Credentials
    "secretsmanager:GetSecretValue": {"category": "data_access", "severity": 4, "label": "Read Secret"},
    "secretsmanager:DescribeSecret": {"category": "data_access", "severity": 2, "label": "Secret Metadata"},
    "ssm:GetParameter": {"category": "data_access", "severity": 3, "label": "Read Parameter"},
    "ssm:GetParameters": {"category": "data_access", "severity": 3, "label": "Read Multiple Parameters"},
    "ssm:GetParametersByPath": {"category": "data_access", "severity": 3, "label": "Read Parameter Path"},
    "kms:Decrypt": {"category": "data_access", "severity": 4, "label": "Decrypt Data"},
    "kms:GenerateDataKey": {"category": "data_access", "severity": 4, "label": "Generate Data Key"},

    # Logs & Analytics
    "logs:GetLogEvents": {"category": "data_access", "severity": 2, "label": "Read Logs"},
    "logs:FilterLogEvents": {"category": "data_access", "severity": 2, "label": "Search Logs"},
    "athena:GetQueryResults": {"category": "data_access", "severity": 3, "label": "Athena Results"},
    "glue:GetTable": {"category": "data_access", "severity": 2, "label": "Read Glue Table"},
    "glue:GetPartitions": {"category": "data_access", "severity": 2, "label": "Get Partitions"},

    # RDS Data Access
    "rds-data:ExecuteStatement": {"category": "data_access", "severity": 3, "label": "Execute SQL"},

    # ================= PRIVILEGE ESCALATION (Severity 4) =================
    "iam:CreateUser": {"category": "privilege_escalation", "severity": 4, "label": "Create User"},
    "iam:CreateRole": {"category": "privilege_escalation", "severity": 4, "label": "Create Role"},
    "iam:AttachUserPolicy": {"category": "privilege_escalation", "severity": 4, "label": "Attach User Policy"},
    "iam:AttachRolePolicy": {"category": "privilege_escalation", "severity": 4, "label": "Attach Role Policy"},
    "iam:AttachGroupPolicy": {"category": "privilege_escalation", "severity": 4, "label": "Attach Group Policy"},
    "iam:PutUserPolicy": {"category": "privilege_escalation", "severity": 4, "label": "Inline User Policy"},
    "iam:PutRolePolicy": {"category": "privilege_escalation", "severity": 4, "label": "Inline Role Policy"},
    "iam:PutGroupPolicy": {"category": "privilege_escalation", "severity": 4, "label": "Inline Group Policy"},
    "iam:CreateAccessKey": {"category": "privilege_escalation", "severity": 4, "label": "Create Access Key"},
    "iam:CreateLoginProfile": {"category": "privilege_escalation", "severity": 4, "label": "Console Access"},
    "iam:UpdateAssumeRolePolicy": {"category": "privilege_escalation", "severity": 4, "label": "Trust Policy Edit"},
    "iam:AddUserToGroup": {"category": "privilege_escalation", "severity": 4, "label": "Add User to Group"},
    "iam:PassRole": {"category": "privilege_escalation", "severity": 4, "label": "Pass Role"},
    "sts:AssumeRole": {"category": "privilege_escalation", "severity": 4, "label": "Assume Role"},
    "iam:UpdateLoginProfile": {"category": "privilege_escalation", "severity": 4, "label": "Update Login Profile"},
    "iam:CreatePolicyVersion": {"category": "privilege_escalation", "severity": 4, "label": "Create Policy Version"},
    "iam:SetDefaultPolicyVersion": {"category": "privilege_escalation", "severity": 4, "label": "Set Default Policy Version"},
    "iam:PutRolePermissionsBoundary": {"category": "privilege_escalation", "severity": 4, "label": "Set Permissions Boundary"},

    # ================= RESOURCE ABUSE (Severity 3-4) =================
    "iam:DetachUserPolicy": {"category": "resource_abuse", "severity": 4, "label": "Detach User Policy"},
    "iam:DeleteUser": {"category": "resource_abuse", "severity": 4, "label": "Delete User"},
    "iam:DeleteRole": {"category": "resource_abuse", "severity": 4, "label": "Delete Role"},
    "iam:DeletePolicy": {"category": "resource_abuse", "severity": 4, "label": "Delete Policy"},
    "ec2:RunInstances": {"category": "resource_abuse", "severity": 3, "label": "Launch Instance"},
    "ec2:TerminateInstances": {"category": "resource_abuse", "severity": 4, "label": "Terminate Instance"},
    "ec2:CreateSecurityGroup": {"category": "resource_abuse", "severity": 3, "label": "Create Security Group"},
    "ec2:ModifySecurityGroupRules": {"category": "resource_abuse", "severity": 3, "label": "Modify Security Group"},
    "ec2:AuthorizeSecurityGroupIngress": {"category": "resource_abuse", "severity": 3, "label": "Allow Inbound"},

    "s3:PutObject": {"category": "resource_abuse", "severity": 3, "label": "Upload Object"},
    "s3:DeleteObject": {"category": "resource_abuse", "severity": 4, "label": "Delete Object"},
    "s3:DeleteObjects": {"category": "resource_abuse", "severity": 4, "label": "Bulk Delete Objects"},
    "s3:DeleteBucket": {"category": "resource_abuse", "severity": 4, "label": "Delete Bucket"},
    "s3:PutBucketPolicy": {"category": "resource_abuse", "severity": 4, "label": "Change Bucket Policy"},
    "s3:PutBucketAcl": {"category": "resource_abuse", "severity": 4, "label": "Change Bucket ACL"},
    "s3:DeleteBucketPolicy": {"category": "resource_abuse", "severity": 4, "label": "Delete Bucket Policy"},

    "dynamodb:DeleteTable": {"category": "resource_abuse", "severity": 4, "label": "Delete Table"},
    "dynamodb:PutItem": {"category": "resource_abuse", "severity": 3, "label": "Write Item"},
    "dynamodb:DeleteItem": {"category": "resource_abuse", "severity": 3, "label": "Delete Item"},
    "dynamodb:BatchWriteItem": {"category": "resource_abuse", "severity": 3, "label": "Bulk Write"},

    "lambda:DeleteFunction": {"category": "resource_abuse", "severity": 4, "label": "Delete Lambda"},
    "lambda:UpdateFunctionCode": {"category": "resource_abuse", "severity": 4, "label": "Update Function Code"},
    "lambda:CreateFunction": {"category": "resource_abuse", "severity": 3, "label": "Create Function"},

    # Audit Log Tampering (Critical)
    "cloudtrail:StopLogging": {"category": "resource_abuse", "severity": 4, "label": "Disable Logging"},
    "cloudtrail:DeleteTrail": {"category": "resource_abuse", "severity": 4, "label": "Delete Trail"},
    "logs:DeleteLogGroup": {"category": "resource_abuse", "severity": 4, "label": "Delete Logs"},
    "logs:DeleteLogStream": {"category": "resource_abuse", "severity": 3, "label": "Delete Log Stream"},
    "logs:PutRetentionPolicy": {"category": "resource_abuse", "severity": 3, "label": "Reduce Log Retention"},

    # Container & Orchestration
    "ecs:RunTask": {"category": "resource_abuse", "severity": 3, "label": "Run ECS Task"},
    "ecs:StopTask": {"category": "resource_abuse", "severity": 3, "label": "Stop Task"},
    "eks:CreateCluster": {"category": "resource_abuse", "severity": 4, "label": "Create EKS Cluster"},
    "eks:DeleteCluster": {"category": "resource_abuse", "severity": 4, "label": "Delete EKS Cluster"},

    # Network & Registry
    "elasticloadbalancing:CreateLoadBalancer": {"category": "resource_abuse", "severity": 3, "label": "Create ELB"},
    "elasticloadbalancing:DeleteLoadBalancer": {"category": "resource_abuse", "severity": 4, "label": "Delete ELB"},
    "ecr:DeleteRepository": {"category": "resource_abuse", "severity": 4, "label": "Delete Repo"},
    "ecr:PutImage": {"category": "resource_abuse", "severity": 3, "label": "Push Image"},

    # Analytics
    "athena:StartQueryExecution": {"category": "resource_abuse", "severity": 2, "label": "Run Query"},
    "glue:CreateJob": {"category": "resource_abuse", "severity": 3, "label": "Create Glue Job"},
    "glue:CreateDatabase": {"category": "resource_abuse", "severity": 3, "label": "Create Database"},
    "redshift:DeleteCluster": {"category": "resource_abuse", "severity": 4, "label": "Delete Redshift"},
}

# ========== STATISTICS & VALIDATION ==========
def get_stats():
    categories = {}
    severities = {}
    for api, data in AWS_API_TAXONOMY.items():
        cat = data["category"]
        sev = data["severity"]
        categories[cat] = categories.get(cat, 0) + 1
        severities[sev] = severities.get(sev, 0) + 1
    return {
        "total_apis": len(AWS_API_TAXONOMY),
        "categories": categories,
        "severities": severities
    }

if __name__ == "__main__":
    stats = get_stats()
    print(f"Total APIs: {stats['total_apis']}")
    print(f"Category Breakdown: {stats['categories']}")
    print(f"Severity Distribution: {stats['severities']}")
    
    # Breakdown
    for cat in ["reconnaissance", "data_access", "privilege_escalation", "resource_abuse"]:
        apis = [a for a, d in AWS_API_TAXONOMY.items() if d["category"] == cat]
        print(f"\n{cat.upper()}: {len(apis)} APIs")