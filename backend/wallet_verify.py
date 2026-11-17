"""Read-only provider checks for encrypted project credentials.

A successful check confirms only the specific operation tested, not every
permission needed by a future forensic collection.
"""
from datetime import datetime, timezone
import json

from crypto import decrypt_blob
from db.database import SessionLocal
from db.models import AuditLog, CredentialWalletEntry, Project


def _check(provider: str, credentials: dict) -> None:
    if provider == 'aws':
        import boto3
        from botocore.config import Config
        boto3.client('sts', aws_access_key_id=credentials['access_key_id'],
                     aws_secret_access_key=credentials['secret_access_key'], region_name=credentials['region'],
                     config=Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 1})).get_caller_identity()
    elif provider == 'gcp':
        from google.cloud import logging_v2
        from google.oauth2 import service_account
        info = json.loads(credentials['service_account_json'])
        auth = service_account.Credentials.from_service_account_info(info)
        client = logging_v2.Client(project=info['project_id'], credentials=auth)
        try:
            next(iter(client.list_entries(page_size=1, max_results=1, filter_='logName:"cloudaudit.googleapis.com"')), None)
        finally:
            client.close()
    elif provider == 'azure':
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource.resources import ResourceManagementClient
        auth = ClientSecretCredential(credentials['tenant_id'], credentials['client_id'], credentials['client_secret'])
        client = ResourceManagementClient(auth, credentials['subscription_id'])
        try:
            next(iter(client.resource_groups.list()), None)
        finally:
            client.close()
            auth.close()
    elif provider in ('stripe', 'twilio'):
        import requests
        session = requests.Session()
        session.trust_env = False
        try:
            if provider == 'stripe':
                response = session.get('https://api.stripe.com/v1/events', params={'limit': 1},
                                       auth=(credentials['api_key'], ''), timeout=(5, 15), allow_redirects=False)
            else:
                sid = credentials['account_sid']
                response = session.get(f'https://api.twilio.com/2010-04-01/Accounts/{sid}.json',
                                       auth=(sid, credentials['auth_token']), timeout=(5, 15), allow_redirects=False)
            if response.status_code in (401, 403):
                raise PermissionError('Provider rejected the credential or permission')
            if response.status_code < 200 or response.status_code >= 300:
                raise RuntimeError('Provider check failed')
        finally:
            session.close()
    else:
        raise ValueError('Unsupported provider')


def verify_entry(entry_id: str, expected_iv: str, actor_id: str | None = None) -> None:
    """Check one version of a wallet row; do not overwrite a newer credential."""
    db = SessionLocal()
    try:
        entry = db.get(CredentialWalletEntry, entry_id)
        if not entry or entry.iv != expected_iv:
            return
        provider = entry.provider
        try:
            _check(provider, decrypt_blob(entry.encrypted_blob, entry.iv))
            status, error = 'ok', None
        except PermissionError:
            status, error = 'error', 'Provider rejected authentication or permission for this check.'
        except Exception:
            # Provider exceptions may contain secrets or response bodies: do not log them.
            status, error = 'error', 'Verification failed. Check credentials, permissions, and provider connectivity.'
        # Reload conditionally: updates/deletion while the provider call was in flight win.
        updated = db.query(CredentialWalletEntry).filter_by(id=entry_id, iv=expected_iv).update({
            'verification_status': status, 'verification_error': error,
            'last_verified_at': datetime.now(timezone.utc)}, synchronize_session=False)
        if updated:
            project = db.get(Project, entry.project_id)
            if project:
                db.add(AuditLog(organisation_id=project.organisation_id, actor_user_id=actor_id,
                                project_id=project.id, action='wallet.verified', detail={'provider': provider, 'status': status}))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
