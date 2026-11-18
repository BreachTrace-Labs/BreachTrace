"""Construct the project's independent GCP log reader; never use detected secrets."""
import json

_LOG_SCOPE = 'https://www.googleapis.com/auth/logging.read'
_CLOUD_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'


def reader_project_id(reader):
    if 'service_account_json' in reader:
        return json.loads(reader['service_account_json'])['project_id']
    if reader.get('auth_mode') == 'impersonation':
        return reader['project_id']
    raise ValueError('Unsupported GCP reader configuration')


def reader_credentials(reader):
    if 'service_account_json' in reader:
        from google.oauth2 import service_account
        info = json.loads(reader['service_account_json'])
        return info['project_id'], service_account.Credentials.from_service_account_info(info, scopes=[_LOG_SCOPE])
    if reader.get('auth_mode') == 'impersonation':
        import google.auth
        from google.auth import impersonated_credentials
        if reader.get('source_service_account_json'):
            from google.oauth2 import service_account
            source = service_account.Credentials.from_service_account_info(
                json.loads(reader['source_service_account_json']), scopes=[_CLOUD_SCOPE])
        else:
            source, _ = google.auth.default(scopes=[_CLOUD_SCOPE])
        credentials = impersonated_credentials.Credentials(
            source_credentials=source, target_principal=reader['reader_service_account'],
            target_scopes=[_LOG_SCOPE], lifetime=3600)
        return reader['project_id'], credentials
    raise ValueError('Unsupported GCP reader configuration')
