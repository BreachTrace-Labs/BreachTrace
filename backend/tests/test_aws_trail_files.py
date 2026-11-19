import gzip
import io
import json
from datetime import datetime, timezone

import pytest

from collectors.aws import AWSCloudTrailCollector
from routers.wallet import validate_credentials


NOW = datetime(2026, 11, 19, 8, 40, tzinfo=timezone.utc)
READER = {'access_key_id': 'AKIAIOSFODNN7EXAMPLE', 'secret_access_key': 'synthetic',
          'region': 'ap-southeast-2', 'trail_bucket': 'example-trail-bucket',
          'trail_prefix': 'AWSLogs/example/CloudTrail/'}


def test_trail_files_use_wallet_filter_and_deduplicate(monkeypatch):
    import boto3
    matching = {'eventID': 'event-1', 'eventTime': NOW.isoformat(), 'eventName': 'GetObject',
                'eventSource': 's3.amazonaws.com', 'awsRegion': 'ap-southeast-2',
                'userIdentity': {'accessKeyId': 'target', 'arn': 'arn:example'},
                'requestParameters': {'bucketName': 'synthetic', 'key': 'example'},
                'errorCode': 'AccessDenied'}
    other = {**matching, 'eventID': 'event-2', 'userIdentity': {'accessKeyId': 'other'}}
    blob = gzip.compress(json.dumps({'Records': [matching, other]}).encode())
    calls = []

    class S3:
        def get_paginator(self, name):
            assert name == 'list_objects_v2'
            return self
        def paginate(self, **kwargs):
            calls.append(kwargs)
            return [{'Contents': [{'Key': READER['trail_prefix'] + 'one.json.gz', 'Size': len(blob)}]},
                    {'Contents': [{'Key': READER['trail_prefix'] + 'two.json.gz', 'Size': len(blob)}]}]
        def get_object(self, **kwargs):
            return {'Body': io.BytesIO(blob)}

    class Trail:
        def lookup_events(self, **kwargs):
            return {'Events': []}

    def client(service, **kwargs):
        assert kwargs['aws_access_key_id'] == READER['access_key_id']
        return S3() if service == 's3' else Trail()

    monkeypatch.setattr(boto3, 'client', client)
    events = AWSCloudTrailCollector(READER).collect('target', NOW, NOW)
    assert len(events) == 1
    assert events[0].source_record_id == 'event-1'
    assert events[0].success is False
    assert events[0].affected_resource == 'synthetic/example'
    assert events[0].raw_data['evidence_source']['sha256_compressed']
    assert calls == [{'Bucket': READER['trail_bucket'], 'Prefix': READER['trail_prefix']}]


def test_wallet_requires_bucket_and_prefix_together():
    from fastapi import HTTPException
    validate_credentials('aws', READER)
    with pytest.raises(HTTPException):
        validate_credentials('aws', {k: v for k, v in READER.items() if k != 'trail_prefix'})
