import json
import logging
from datetime import datetime, timedelta

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

import config
from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# CloudTrail has up to 15-minute delivery delay — add a buffer when querying.
_CLOUDTRAIL_END_BUFFER_MINUTES = 20


def _json_safe_raw_event(raw_event: dict) -> dict:
    """Prepare the raw CloudTrail event for JSON/JSONB storage."""
    serializable_event = dict(raw_event)
    event_time = serializable_event.get("EventTime")
    if isinstance(event_time, datetime):
        serializable_event["EventTime"] = event_time.isoformat()
    return serializable_event


def _extract_resource_from_params(
    nested_event: dict, api_action: str
) -> tuple[str | None, str | None]:
    """
    Extract (resource_name, resource_type) from requestParameters when the top-level
    CloudTrail Resources array is empty.  Covers the most common AWS service patterns.
    Returns (None, None) when no resource can be inferred.
    """
    params = nested_event.get("requestParameters") or {}
    if not params or not isinstance(params, dict):
        return None, None

    # S3 object-level operations
    if api_action in (
        "GetObject", "PutObject", "DeleteObject", "HeadObject",
        "GetObjectTagging", "GetObjectVersion", "SelectObjectContent",
        "GetObjectAcl", "RestoreObject", "CopyObject",
    ):
        bucket = params.get("bucketName")
        key = params.get("key") or params.get("Key")
        if bucket and key:
            return f"{bucket}/{key}", "AWS::S3::Object"
        if bucket:
            return bucket, "AWS::S3::Bucket"

    # S3 bucket-level operations
    if api_action in (
        "ListObjects", "ListObjectsV2", "ListBucket", "CreateBucket",
        "GetBucketPolicy", "GetBucketAcl", "GetBucketLocation",
        "GetBucketEncryption", "GetBucketVersioning", "GetBucketTagging",
        "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "DeleteBucket",
    ):
        bucket = params.get("bucketName")
        if bucket:
            return bucket, "AWS::S3::Bucket"

    # EC2 instance launch
    if api_action == "RunInstances":
        image_id = params.get("imageId")
        if image_id:
            return image_id, "AWS::EC2::Image"

    # IAM user operations
    if api_action in (
        "CreateUser", "GetUser", "DeleteUser", "UpdateUser",
        "ListAccessKeys", "CreateLoginProfile", "UpdateLoginProfile",
        "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "CreateAccessKey",
    ):
        username = params.get("userName")
        if username:
            return username, "AWS::IAM::User"

    # IAM role operations
    if api_action in (
        "CreateRole", "GetRole", "DeleteRole",
        "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy",
        "UpdateAssumeRolePolicy", "PassRole",
    ):
        role_name = params.get("roleName")
        if role_name:
            return role_name, "AWS::IAM::Role"

    # Secrets Manager
    if api_action in ("GetSecretValue", "DescribeSecret", "PutSecretValue", "DeleteSecret"):
        secret_id = params.get("secretId")
        if secret_id:
            return secret_id, "AWS::SecretsManager::Secret"

    # SSM Parameter Store
    if api_action in ("GetParameter", "GetParameters", "GetParametersByPath", "PutParameter", "DeleteParameter"):
        name = params.get("name") or params.get("names")
        if isinstance(name, list):
            name = ", ".join(str(n) for n in name[:3])
        if name:
            return name, "AWS::SSM::Parameter"

    # DynamoDB
    if api_action in (
        "GetItem", "PutItem", "DeleteItem", "UpdateItem",
        "Query", "Scan", "BatchGetItem", "BatchWriteItem",
        "DescribeTable", "DeleteTable", "ExportTableToPointInTime",
    ):
        table_name = params.get("tableName")
        if table_name:
            return table_name, "AWS::DynamoDB::Table"

    # Lambda
    if api_action in (
        "GetFunction", "CreateFunction", "UpdateFunctionCode",
        "DeleteFunction", "InvokeFunction",
    ):
        func_name = params.get("functionName")
        if func_name:
            return func_name, "AWS::Lambda::Function"

    # RDS
    if api_action in (
        "CreateDBInstance", "DeleteDBInstance", "DescribeDBInstances",
        "ModifyDBInstance", "CreateDBCluster", "RestoreDBInstanceFromDBSnapshot",
    ):
        db_id = (
            params.get("dBInstanceIdentifier")
            or params.get("dbInstanceIdentifier")
            or params.get("dBClusterIdentifier")
        )
        if db_id:
            return db_id, "AWS::RDS::DBInstance"

    # KMS
    if api_action in ("Decrypt", "GenerateDataKey", "DescribeKey", "Encrypt"):
        key_id = params.get("keyId")
        if key_id:
            return key_id, "AWS::KMS::Key"

    # SNS
    if api_action in ("Publish", "CreateTopic", "Subscribe", "SetSubscriptionAttributes"):
        topic_arn = params.get("topicArn")
        if topic_arn:
            return topic_arn, "AWS::SNS::Topic"

    # SQS
    if api_action in ("SendMessage", "SendMessageBatch", "ReceiveMessage", "DeleteMessage"):
        queue_url = params.get("queueUrl")
        if queue_url:
            return queue_url.rstrip("/").split("/")[-1], "AWS::SQS::Queue"

    # SES
    if api_action in ("SendEmail", "SendRawEmail", "SendBulkTemplatedEmail", "SendBulkEmail"):
        source = params.get("source")
        if source:
            return source, "AWS::SES::Identity"

    # EKS / ECS cluster
    if api_action in ("CreateCluster", "DescribeCluster", "DeleteCluster"):
        name = params.get("name")
        if name:
            return name, "AWS::EKS::Cluster"

    # SageMaker
    if api_action in ("CreateTrainingJob", "CreateEndpoint", "CreateNotebookInstance"):
        for key in ("trainingJobName", "endpointName", "notebookInstanceName"):
            value = params.get(key)
            if value:
                return value, "AWS::SageMaker::Resource"

    # ElastiCache
    if api_action in ("CreateCacheCluster", "CreateReplicationGroup"):
        cluster_id = params.get("cacheClusterId") or params.get("replicationGroupId")
        if cluster_id:
            return cluster_id, "AWS::ElastiCache::Cluster"

    return None, None


def _map_cloudtrail_event(raw_event: dict) -> ForensicEvent:
    """Convert one boto3 CloudTrail lookup event into the shared ForensicEvent schema."""
    nested_event = {}
    cloudtrail_event = raw_event.get("CloudTrailEvent")
    if isinstance(cloudtrail_event, str):
        try:
            parsed = json.loads(cloudtrail_event)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            nested_event = parsed

    resources = raw_event.get("Resources") or []
    first_resource = resources[0] if resources else {}
    error_code = raw_event.get("ErrorCode") or nested_event.get("errorCode")

    affected_resource = first_resource.get("ResourceName")
    resource_type = first_resource.get("ResourceType")

    # Fall back to requestParameters when the Resources array yields nothing
    if not affected_resource:
        api_action = raw_event.get("EventName", "")
        fallback_resource, fallback_type = _extract_resource_from_params(nested_event, api_action)
        if fallback_resource:
            affected_resource = fallback_resource
            resource_type = resource_type or fallback_type

    return ForensicEvent(
        platform="aws",
        timestamp=raw_event["EventTime"],
        api_action=raw_event["EventName"],
        event_source=raw_event.get("EventSource") or nested_event.get("eventSource"),
        source_ip=raw_event.get("SourceIPAddress") or nested_event.get("sourceIPAddress"),
        user_agent=raw_event.get("UserAgent") or nested_event.get("userAgent"),
        affected_resource=affected_resource,
        resource_type=resource_type,
        success=error_code is None,
        error_code=error_code,
        raw_data=_json_safe_raw_event(raw_event),
    )


class AWSCloudTrailCollector(BaseCollector):
    """
    Collects AWS CloudTrail events for a given access key ID during an exposure window.

    Uses the admin AWS credentials (from config) to query CloudTrail — the leaked
    key's ID is passed as a lookup attribute, not used for authentication.
    """

    platform = "aws"

    def __init__(self) -> None:
        self._client = boto3.client(
            "cloudtrail",
            region_name=config.AWS_REGION,
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        )

    # ------------------------------------------------------------------
    # Retryable CloudTrail lookup (handles throttling / transient errors)
    # ------------------------------------------------------------------
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _lookup_page(
        self,
        access_key_id: str,
        start_time: datetime,
        end_time: datetime,
        next_token: str | None = None,
    ) -> dict:
        """Execute a single paginated CloudTrail LookupEvents call."""
        params: dict = {
            "LookupAttributes": [
                {
                    "AttributeKey": "AccessKeyId",
                    "AttributeValue": access_key_id,
                }
            ],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": 50,
        }
        if next_token:
            params["NextToken"] = next_token

        return self._client.lookup_events(**params)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        Query CloudTrail for all API calls made with *credential* (an AKIA… key ID)
        between *start_time* and *end_time*.

        Adds a 20-minute buffer to *end_time* to account for CloudTrail's delivery delay.
        Paginates automatically until all events are retrieved.
        """
        adjusted_end = end_time + timedelta(minutes=_CLOUDTRAIL_END_BUFFER_MINUTES)
        logger.info(
            "CloudTrail lookup: key=%s window=%s → %s (buffered to %s)",
            credential,
            start_time.isoformat(),
            end_time.isoformat(),
            adjusted_end.isoformat(),
        )

        events: list[ForensicEvent] = []
        next_token: str | None = None

        while True:
            response = self._lookup_page(credential, start_time, adjusted_end, next_token)

            for raw_event in response.get("Events", []):
                try:
                    forensic_event = _map_cloudtrail_event(raw_event)
                    events.append(forensic_event)
                except Exception:
                    logger.exception("Failed to map CloudTrail event: %s", raw_event.get("EventId"))

            next_token = response.get("NextToken")
            if not next_token:
                break

        logger.info("CloudTrail returned %d events for key %s", len(events), credential)
        return events
