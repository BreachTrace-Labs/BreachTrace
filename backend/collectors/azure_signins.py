"""Bounded, on-demand Microsoft Graph beta service-principal sign-in evidence."""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import uuid

import httpx

_GRAPH = 'https://graph.microsoft.com/beta/auditLogs/signIns'
_MAX_PAGES = 5


class SignInCollectionError(Exception):
    pass


def _safe_next(url):
    parsed = urlsplit(url)
    return (parsed.scheme == 'https' and parsed.netloc == 'graph.microsoft.com'
            and parsed.path == '/beta/auditLogs/signIns' and not parsed.fragment
            and not parsed.username and not parsed.password)


def collect_signins(reader, app_id, key_id=None, *, now=None, client=None):
    """Return bounded, locally identity-checked records; never retain access tokens."""
    from azure.identity import ClientSecretCredential
    try:
        app_id = str(uuid.UUID(app_id))
        key_id = str(uuid.UUID(key_id)) if key_id else None
    except (ValueError, TypeError, AttributeError):
        raise SignInCollectionError('Invalid application or credential key ID.') from None
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=30)
    fmt = lambda t: t.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    query = (f"(createdDateTime ge {fmt(start)} and createdDateTime le {fmt(now)}) "
             "and signInEventTypes/any(t: t eq 'servicePrincipal') "
             f"and appId eq '{app_id}'")
    try:
        credential = ClientSecretCredential(reader['tenant_id'], reader['client_id'], reader['client_secret'])
        token = credential.get_token('https://graph.microsoft.com/.default').token
        credential.close()
    except Exception:
        raise SignInCollectionError('Could not authenticate the Azure reader for Microsoft Graph.') from None
    rows = []
    next_url = _GRAPH
    params = {'$filter': query, '$top': '100'}
    truncated = False
    try:
        with httpx.Client(timeout=15, follow_redirects=False) if client is None else _borrow(client) as http:
            for _ in range(_MAX_PAGES):
                if not _safe_next(next_url):
                    raise SignInCollectionError('Microsoft Graph returned an invalid continuation URL.')
                response = http.get(next_url, params=params, headers={'Authorization': f'Bearer {token}'})
                if response.status_code in (401, 403):
                    raise SignInCollectionError('Microsoft Graph access denied. Check AuditLog.Read.All admin consent and the tenant license.')
                if response.status_code != 200:
                    raise SignInCollectionError('Microsoft Graph sign-in collection failed. Check connectivity and try again.')
                page = response.json()
                if not isinstance(page, dict) or not isinstance(page.get('value'), list):
                    raise SignInCollectionError('Microsoft Graph returned an invalid sign-in response.')
                for item in page['value']:
                    if not isinstance(item, dict) or str(item.get('appId', '')).lower() != app_id:
                        continue
                    if 'servicePrincipal' not in (item.get('signInEventTypes') or []):
                        continue
                    try:
                        timestamp = datetime.fromisoformat(str(item.get('createdDateTime', '')).replace('Z', '+00:00'))
                        if timestamp.tzinfo is None or not start <= timestamp <= now:
                            continue
                    except (ValueError, TypeError):
                        continue
                    raw_key = item.get('servicePrincipalCredentialKeyId')
                    try:
                        event_key = str(uuid.UUID(raw_key)) if raw_key else None
                    except (ValueError, TypeError, AttributeError):
                        event_key = None
                    status = item.get('status') if isinstance(item.get('status'), dict) else {}
                    code = status.get('errorCode')
                    rows.append({'id': str(item.get('id') or '')[:100], 'timestamp': timestamp.isoformat(),
                                 'source_ip': str(item.get('ipAddress') or '')[:100] or None,
                                 'resource': str(item.get('resourceDisplayName') or '')[:200] or None,
                                 'outcome': 'success' if code == 0 else 'failure' if isinstance(code, int) else 'unknown',
                                 'key_match': ('matched' if event_key == key_id else 'different_key') if event_key and key_id else 'unavailable'})
                next_url = page.get('@odata.nextLink')
                params = None
                if not next_url:
                    break
                if not isinstance(next_url, str):
                    raise SignInCollectionError('Microsoft Graph returned an invalid continuation URL.')
            else:
                truncated = bool(next_url)
    except SignInCollectionError:
        raise
    except Exception:
        raise SignInCollectionError('Microsoft Graph sign-in collection failed. Check connectivity and try again.') from None
    return {'events': rows, 'range_start': fmt(start), 'range_end': fmt(now), 'truncated': truncated,
            'key_comparison': 'operator_reported' if key_id else 'not_provided'}


class _borrow:
    def __init__(self, client): self.client = client
    def __enter__(self): return self.client
    def __exit__(self, *_): return False
