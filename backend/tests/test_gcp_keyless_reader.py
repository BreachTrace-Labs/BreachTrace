import pytest
import json
from fastapi import HTTPException


def test_impersonation_uses_adc_only_as_source_and_restricted_logging_target(monkeypatch):
    import google.auth
    from google.auth import impersonated_credentials
    from gcp_reader import reader_credentials
    from routers.wallet import validate_credentials
    seen = []
    monkeypatch.setattr(google.auth, 'default', lambda **kwargs: (seen.append(('source', kwargs)) or 'source', 'source-project'))
    monkeypatch.setattr(impersonated_credentials, 'Credentials', lambda **kwargs: seen.append(('target', kwargs)) or 'target')
    values = validate_credentials('gcp', {'auth_mode':'impersonation', 'project_id':'example-project', 'reader_service_account':'reader@example-project.iam.gserviceaccount.com'})
    project, creds = reader_credentials(values)
    assert (project, creds) == ('example-project', 'target')
    assert seen[0][1]['scopes'] == ['https://www.googleapis.com/auth/cloud-platform']
    assert seen[1][1]['source_credentials'] == 'source'
    assert seen[1][1]['target_principal'] == values['reader_service_account']
    assert seen[1][1]['target_scopes'] == ['https://www.googleapis.com/auth/logging.read']


def test_impersonation_configuration_does_not_fall_back_on_source_failure(monkeypatch):
    import google.auth
    from gcp_reader import reader_credentials
    from routers.wallet import validate_credentials
    with pytest.raises(HTTPException):
        validate_credentials('gcp', {'auth_mode':'impersonation','project_id':'example-project','reader_service_account':'not-an-email'})
    with pytest.raises(HTTPException):
        validate_credentials('gcp', {'auth_mode':'impersonation','project_id':'example-project','reader_service_account':'reader@example-project.iam.gserviceaccount.com','service_account_json':'secret'})
    monkeypatch.setattr(google.auth, 'default', lambda **kwargs: (_ for _ in ()).throw(RuntimeError('no ADC')))
    with pytest.raises(RuntimeError, match='no ADC'):
        reader_credentials({'auth_mode':'impersonation','project_id':'example-project','reader_service_account':'reader@example-project.iam.gserviceaccount.com'})


def test_collector_rejects_investigating_its_own_reader_identity():
    from collectors.gcp import GCPAuditLogCollector
    collector = object.__new__(GCPAuditLogCollector)
    collector._reader_principal = 'reader@example-project.iam.gserviceaccount.com'
    with pytest.raises(ValueError, match='must be separate'):
        collector.collect('READER@example-project.iam.gserviceaccount.com', None, None)


def test_wallet_source_json_is_used_only_to_impersonate_reader(monkeypatch):
    from google.oauth2 import service_account
    from google.auth import impersonated_credentials
    import google.auth
    from gcp_reader import reader_credentials
    from routers.wallet import validate_credentials

    source = {'type': 'service_account', 'project_id': 'source-project', 'private_key': 'test-only',
              'client_email': 'source@source-project.iam.gserviceaccount.com',
              'token_uri': 'https://oauth2.googleapis.com/token'}
    values = validate_credentials('gcp', {'auth_mode': 'impersonation', 'project_id': 'example-project',
        'reader_service_account': 'reader@example-project.iam.gserviceaccount.com',
        'source_service_account_json': json.dumps(source)})
    seen = []
    monkeypatch.setattr(google.auth, 'default', lambda **_: pytest.fail('must not fall back to ADC'))
    monkeypatch.setattr(service_account.Credentials, 'from_service_account_info',
                        lambda info, scopes: seen.append((info, scopes)) or 'source')
    monkeypatch.setattr(impersonated_credentials, 'Credentials', lambda **kwargs: seen.append(kwargs) or 'target')
    assert reader_credentials(values) == ('example-project', 'target')
    assert seen[0] == (source, ['https://www.googleapis.com/auth/cloud-platform'])
    assert seen[1]['source_credentials'] == 'source'
    assert seen[1]['target_principal'] == values['reader_service_account']
    assert seen[1]['target_scopes'] == ['https://www.googleapis.com/auth/logging.read']


def test_wallet_source_json_rejects_untrusted_token_uri():
    from routers.wallet import validate_credentials
    source = {'type': 'service_account', 'project_id': 'example-project', 'private_key': 'test-only',
              'client_email': 'source@example-project.iam.gserviceaccount.com', 'token_uri': 'https://example.com/token'}
    with pytest.raises(HTTPException):
        validate_credentials('gcp', {'auth_mode': 'impersonation', 'project_id': 'example-project',
            'reader_service_account': 'reader@example-project.iam.gserviceaccount.com',
            'source_service_account_json': json.dumps(source)})


def test_collector_rejects_investigating_its_impersonation_source():
    from collectors.gcp import GCPAuditLogCollector
    collector = object.__new__(GCPAuditLogCollector)
    collector._reader_principal = 'reader@example-project.iam.gserviceaccount.com'
    collector._source_principal = 'source@example-project.iam.gserviceaccount.com'
    with pytest.raises(ValueError, match='impersonation source must be separate'):
        collector.collect('SOURCE@example-project.iam.gserviceaccount.com', None, None)
