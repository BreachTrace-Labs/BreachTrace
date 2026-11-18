"""Project readers must be selected by the incident, never by a global default."""
from datetime import datetime, timezone

import pytest

from crypto import encrypt_blob
from db.crud import create_incident
from db.models import CredentialWalletEntry, IncidentRecord


@pytest.mark.parametrize('provider,values,credential,hint', [
    ('aws', {'access_key_id': 'reader-a', 'secret_access_key': 'secret-a', 'region': 'us-east-1'}, 'AKIA' + 'A' * 16, 'AKIA****AAAA'),
    ('gcp', {'service_account_json': '{"project_id":"project-a"}'}, 'service@example.test', 'service...'),
    ('azure', {'tenant_id': 'tenant-a', 'client_id': 'reader-a', 'client_secret': 'secret-a', 'subscription_id': 'sub-a'}, 'app-a', 'app-a'),
    ('stripe', {'api_key': 'rk_test_readerA'}, 'sk_test_exposedSecret', 'sk_test_****cret'),
    ('twilio', {'account_sid': 'AC' + 'a' * 32, 'api_key_sid': 'SK' + 'b' * 32, 'api_key_secret': 'secret-a'}, 'AC' + 'a' * 32, 'ACaa****aaaa'),
])
def test_pipeline_uses_incident_project_reader(sqlite_factory, monkeypatch, provider, values, credential, hint):
    import pipeline
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    monkeypatch.setattr(pipeline, 'SessionLocal', sqlite_factory)
    monkeypatch.setattr(pipeline, '_index_incident_safely', lambda *_: None)
    monkeypatch.setattr(pipeline, '_upgrade_report', lambda *_: False)
    calls = []
    class Collector:
        def __init__(self, **kwargs):
            calls.append(('reader', kwargs))
        def collect(self, **kwargs):
            calls.append(('collect', kwargs))
            return []
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, provider, Collector)
    ciphertext, iv = encrypt_blob(values)
    with sqlite_factory() as db:
        db.add(CredentialWalletEntry(project_id='project-a', provider=provider, encrypted_blob=ciphertext,
                                     iv=iv, created_by='admin', verification_status='ok'))
        incident = create_incident(db, credential_type='aws_access_key', credential_hint=hint,
                                   repo_url='https://github.com/example/repo', commit_hash='a' * 40,
                                   exposure_start=datetime.now(timezone.utc), project_id='project-a')
        incident_id, start = incident.incident_id, incident.exposure_start
    pipeline.run_collection_pipeline(incident_id, credential, start, platform=provider)
    expected = {'api_key': values['api_key']} if provider == 'stripe' else {'reader': values}
    assert calls[0] == ('reader', expected)
    assert calls[1][1]['credential'] == (hint if provider == 'stripe' else credential)
    with sqlite_factory() as db:
        assert db.get(IncidentRecord, incident_id).status == 'complete'


@pytest.mark.parametrize('state', ['missing', 'pending', 'error', 'unreadable'])
def test_project_reader_fails_closed(sqlite_factory, monkeypatch, state):
    from collection_credentials import ReaderConfigurationError, project_reader
    monkeypatch.setenv('WALLET_ENCRYPTION_KEY', '12' * 32)
    with sqlite_factory() as db:
        ciphertext, iv = encrypt_blob({'api_key': 'rk_test_otherProject'})
        db.add(CredentialWalletEntry(project_id='other-project', provider='stripe', encrypted_blob=ciphertext,
                                     iv=iv, created_by='admin', verification_status='ok'))
        if state != 'missing':
            db.add(CredentialWalletEntry(project_id='project-a', provider='stripe',
                                         encrypted_blob='invalid' if state == 'unreadable' else ciphertext,
                                         iv=iv, created_by='admin', verification_status='ok' if state == 'unreadable' else state))
        db.commit()
        incident = IncidentRecord(project_id='project-a')
        with pytest.raises(ReaderConfigurationError) as exc:
            project_reader(db, incident, 'stripe')
        assert 'rk_test_otherProject' not in str(exc.value)
        assert project_reader(db, IncidentRecord(project_id=None), 'stripe') is None


def test_collectors_construct_clients_with_wallet_fields(monkeypatch):
    import json
    import boto3
    import azure.identity
    import azure.mgmt.monitor
    import google.cloud.logging
    import google.oauth2.service_account
    import twilio.rest
    from collectors.aws import AWSCloudTrailCollector
    from collectors.azure import AzureActivityLogCollector
    from collectors.gcp import GCPAuditLogCollector
    from collectors.twilio import TwilioUsageCollector

    calls = []
    monkeypatch.setattr(boto3, 'client', lambda *args, **kwargs: calls.append(('aws', args, kwargs)))
    AWSCloudTrailCollector(reader={'access_key_id': 'a', 'secret_access_key': 'b', 'region': 'r'})
    assert calls[-1] == ('aws', ('cloudtrail',), {'region_name': 'r', 'aws_access_key_id': 'a', 'aws_secret_access_key': 'b'})

    monkeypatch.setattr(azure.identity, 'ClientSecretCredential', lambda **kwargs: calls.append(('azure-auth', kwargs)) or 'auth')
    monkeypatch.setattr(azure.mgmt.monitor, 'MonitorManagementClient', lambda auth, sub: calls.append(('azure', auth, sub)))
    AzureActivityLogCollector(reader={'tenant_id': 't', 'client_id': 'c', 'client_secret': 's', 'subscription_id': 'sub'})
    assert calls[-2:] == [('azure-auth', {'tenant_id': 't', 'client_id': 'c', 'client_secret': 's'}), ('azure', 'auth', 'sub')]

    monkeypatch.setattr(google.oauth2.service_account.Credentials, 'from_service_account_info',
                        lambda info, scopes: calls.append(('gcp-auth', info, scopes)) or 'auth')
    monkeypatch.setattr(google.cloud.logging, 'Client', lambda **kwargs: calls.append(('gcp', kwargs)))
    GCPAuditLogCollector(reader={'service_account_json': json.dumps({'project_id': 'project-a'})})
    assert calls[-1] == ('gcp', {'project': 'project-a', 'credentials': 'auth'})

    monkeypatch.setattr(twilio.rest, 'Client', lambda *args: calls.append(('twilio', args)))
    account, key = 'AC' + 'a' * 32, 'SK' + 'b' * 32
    TwilioUsageCollector(reader={'account_sid': account, 'api_key_sid': key, 'api_key_secret': 'secret'})
    assert calls[-1] == ('twilio', (key, 'secret', account))
    TwilioUsageCollector(reader={'account_sid': account, 'auth_token': 'token'})
    assert calls[-1] == ('twilio', (account, 'token'))
