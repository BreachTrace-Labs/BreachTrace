import json
import logging
import gzip
import hashlib
import io
from datetime import datetime, timedelta, timezone

import boto3
from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# CloudTrail has up to 15-minute delivery delay — add a buffer when querying.
_CLOUDTRAIL_END_BUFFER_MINUTES = 20
_MAX_TRAIL_OBJECTS = 1000
_MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_EVENTS = 100_000
_MAX_PAGES = 2_000


def _map_trail_record(record: dict, bucket: str, key: str, digest: str) -> ForensicEvent:
    """Adapt an S3-delivered CloudTrail record to the existing event mapper."""
    when = datetime.fromisoformat(record['eventTime'].replace('Z', '+00:00'))
    if when.tzinfo is None:
        raise ValueError('CloudTrail event time has no timezone')
    event = _map_cloudtrail_event({
        'EventId': record.get('eventID'), 'EventTime': when,
        'EventName': record['eventName'], 'EventSource': record.get('eventSource'),
        'CloudTrailEvent': json.dumps(record),
    })
    event.raw_data['evidence_source'] = {'method': 'cloudtrail-s3', 'bucket': bucket,
                                         'object_key': key, 'sha256_compressed': digest}
    event.principal_id = (record.get('userIdentity') or {}).get('arn')
    event.location = record.get('awsRegion')
    return event


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
        source_record_id=raw_event.get('EventId') or nested_event.get('eventID'),
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

    Uses the project wallet's independent reader to query CloudTrail — the leaked
    key's ID is passed as a lookup attribute, not used for authentication.
    """

    platform = "aws"

    def __init__(self, reader: dict | None = None) -> None:
        if reader is None:
            raise ValueError('Configure an AWS reader in the project credential wallet.')
        self._reader = reader
        self._regions = list(dict.fromkeys([reader['region'], *reader.get('regions', '').split(',')]))
        self._regions = [region for region in self._regions if region]
        self._client = boto3.client(
            "cloudtrail",
            region_name=reader['region'],
            aws_access_key_id=reader['access_key_id'],
            aws_secret_access_key=reader['secret_access_key'],
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

    def _collect_trail_files(self, credential: str, start_time: datetime, end_time: datetime) -> list[ForensicEvent]:
        """Read a bounded set of CloudTrail gzip files using the wallet reader."""
        bucket, prefix = self._reader['trail_bucket'], self._reader['trail_prefix']
        s3 = boto3.client('s3', region_name=self._reader['region'],
                          aws_access_key_id=self._reader['access_key_id'],
                          aws_secret_access_key=self._reader['secret_access_key'])
        output = []
        count = 0
        pages = 0
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
            pages += 1
            if pages > _MAX_PAGES:
                raise ValueError('CloudTrail evidence pagination limit exceeded; narrow the wallet prefix.')
            for item in page.get('Contents', []):
                key = item['Key']
                if not key.endswith('.json.gz'):
                    continue
                count += 1
                if count > _MAX_TRAIL_OBJECTS or item.get('Size', 0) > _MAX_COMPRESSED_BYTES:
                    raise ValueError('CloudTrail evidence exceeds the collection limits; narrow the wallet prefix.')
                body = s3.get_object(Bucket=bucket, Key=key)['Body']
                try:
                    compressed = body.read(_MAX_COMPRESSED_BYTES + 1)
                finally:
                    body.close()
                if len(compressed) > _MAX_COMPRESSED_BYTES:
                    raise ValueError('CloudTrail evidence object is too large.')
                with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                    decoded = stream.read(_MAX_DECOMPRESSED_BYTES + 1)
                if len(decoded) > _MAX_DECOMPRESSED_BYTES:
                    raise ValueError('Decompressed CloudTrail evidence is too large.')
                data = json.loads(decoded)
                if not isinstance(data, dict) or not isinstance(data.get('Records'), list):
                    raise ValueError('Invalid CloudTrail evidence file.')
                digest = hashlib.sha256(compressed).hexdigest()
                for record in data['Records']:
                    if not isinstance(record, dict):
                        raise ValueError('Invalid CloudTrail record.')
                    identity = record.get('userIdentity') or {}
                    if not isinstance(identity, dict) or identity.get('accessKeyId') != credential:
                        continue
                    event = _map_trail_record(record, bucket, key, digest)
                    if start_time <= event.timestamp.astimezone(timezone.utc) <= end_time:
                        output.append(event)
                        if len(output) > _MAX_EVENTS:
                            raise ValueError('CloudTrail event collection limit exceeded; narrow the wallet prefix.')
        return output

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
        if not isinstance(credential, str) or not credential.strip():
            raise ValueError('An AWS access-key ID is required for collection.')
        if credential == self._reader['access_key_id']:
            raise ValueError('The AWS log reader must be separate from the exposed access key.')
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        start_time, end_time = start_time.astimezone(timezone.utc), end_time.astimezone(timezone.utc)
        if end_time < start_time:
            raise ValueError('AWS collection end must not precede its start.')
        if end_time - start_time > timedelta(days=90):
            raise ValueError('AWS collection window exceeds the 90-day limit.')
        adjusted_end = end_time + timedelta(minutes=_CLOUDTRAIL_END_BUFFER_MINUTES)
        logger.info(
            "CloudTrail lookup: window=%s → %s (buffered to %s)",
            start_time.isoformat(),
            end_time.isoformat(),
            adjusted_end.isoformat(),
        )

        events: list[ForensicEvent] = []
        seen = set()
        total_records = 0
        for index, region in enumerate(self._regions):
            if index:
                self._client = boto3.client('cloudtrail', region_name=region,
                    aws_access_key_id=self._reader['access_key_id'],
                    aws_secret_access_key=self._reader['secret_access_key'])
            next_token = None
            tokens = set()
            pages = 0
            while True:
                pages += 1
                if pages > _MAX_PAGES:
                    raise ValueError('CloudTrail management pagination limit exceeded; narrow the collection window.')
                response = self._lookup_page(credential, start_time, adjusted_end, next_token)
                for raw_event in response.get("Events", []):
                    total_records += 1
                    if total_records > _MAX_EVENTS:
                        raise ValueError('CloudTrail event collection limit exceeded; narrow the collection window.')
                    try:
                        forensic_event = _map_cloudtrail_event(raw_event)
                        if forensic_event.source_record_id and forensic_event.source_record_id in seen:
                            continue
                        if forensic_event.source_record_id:
                            seen.add(forensic_event.source_record_id)
                        events.append(forensic_event)
                    except Exception:
                        raise ValueError('Invalid CloudTrail management event; collection was not completed.') from None
                next_token = response.get("NextToken")
                if not next_token:
                    break
                if next_token in tokens:
                    raise ValueError('CloudTrail management pagination repeated a token; collection was not completed.')
                tokens.add(next_token)

        if self._reader.get('trail_bucket') and self._reader.get('trail_prefix'):
            for event in self._collect_trail_files(credential, start_time, end_time):
                if event.source_record_id and event.source_record_id in seen:
                    continue
                if event.source_record_id:
                    seen.add(event.source_record_id)
                events.append(event)
                if len(events) > _MAX_EVENTS:
                    raise ValueError('CloudTrail event collection limit exceeded; narrow the wallet prefix.')
        logger.info("CloudTrail returned %d events", len(events))
        return events
