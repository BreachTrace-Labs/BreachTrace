from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from collectors.aws import AWSCloudTrailCollector
from routers.wallet import validate_credentials


def test_wallet_validates_additional_regions():
    values = {'access_key_id': 'AKIAIOSFODNN7EXAMPLE', 'secret_access_key': 'example',
              'region': 'ap-southeast-2', 'regions': ' us-east-1, ap-southeast-2 '}
    assert validate_credentials('aws', values)['regions'] == 'us-east-1,ap-southeast-2'
    with pytest.raises(HTTPException):
        validate_credentials('aws', {**values, 'regions': 'invalid'})


def test_collection_uses_wallet_regions_and_deduplicates(monkeypatch):
    import boto3

    calls = []
    class Client:
        def __init__(self, region):
            self.region = region

        def lookup_events(self, **kwargs):
            calls.append((self.region, kwargs['LookupAttributes'][0]['AttributeValue']))
            return {'Events': [{'EventId': 'same-id', 'EventName': 'GetCallerIdentity',
                                'EventTime': datetime(2026, 1, 1, tzinfo=timezone.utc)}]}

    monkeypatch.setattr(boto3, 'client', lambda service, **kwargs: Client(kwargs['region_name']))
    collector = AWSCloudTrailCollector({'access_key_id': 'reader', 'secret_access_key': 'secret',
                                         'region': 'ap-southeast-2', 'regions': 'us-east-1'})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = collector.collect('exposed-key-id', now, now)
    assert calls == [('ap-southeast-2', 'exposed-key-id'), ('us-east-1', 'exposed-key-id')]
    assert len(events) == 1 and events[0].source_record_id == 'same-id'


def test_aws_reader_is_required():
    with pytest.raises(ValueError, match='wallet'):
        AWSCloudTrailCollector()


def test_reader_cannot_be_the_investigated_key(monkeypatch):
    import boto3
    monkeypatch.setattr(boto3, 'client', lambda *_args, **_kwargs: None)
    collector = AWSCloudTrailCollector({'access_key_id': 'same-key', 'secret_access_key': 'unused', 'region': 'us-east-1'})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match='reader must be separate'):
        collector.collect('same-key', now, now)


def test_repeated_page_token_stops_collection(monkeypatch):
    import boto3
    monkeypatch.setattr(boto3, 'client', lambda *_args, **_kwargs: None)
    collector = AWSCloudTrailCollector({'access_key_id': 'reader', 'secret_access_key': 'unused', 'region': 'us-east-1'})
    monkeypatch.setattr(collector, '_lookup_page', lambda *_args: {'Events': [], 'NextToken': 'unchanged'})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match='repeated a token'):
        collector.collect('different-key', now, now)
