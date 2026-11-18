"""GitHub OAuth transport helpers; account provisioning is handled separately."""
from dataclasses import dataclass

import httpx


class GitHubOAuthError(Exception):
    """GitHub did not provide a usable authenticated identity."""


@dataclass(frozen=True)
class GitHubIdentity:
    github_id: str
    login: str
    verified_emails: tuple[str, ...]


async def fetch_identity(client: httpx.AsyncClient, *, client_id: str, client_secret: str,
                         code: str, redirect_uri: str, code_verifier: str) -> GitHubIdentity:
    """Exchange a PKCE authorization code and return the authenticated identity.

    The caller owns state validation, the verifier lifecycle, account policy and
    token disposal. The provider token is never returned or persisted here.
    """
    try:
        response = await client.post(
            'https://github.com/login/oauth/access_token',
            headers={'Accept': 'application/json'},
            data={'client_id': client_id, 'client_secret': client_secret, 'code': code,
                  'redirect_uri': redirect_uri, 'code_verifier': code_verifier},
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get('access_token') if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise GitHubOAuthError('GitHub authorization failed')
        headers = {'Accept': 'application/vnd.github+json', 'Authorization': f'Bearer {token}',
                   'X-GitHub-Api-Version': '2022-11-28'}
        user_response = await client.get('https://api.github.com/user', headers=headers)
        user_response.raise_for_status()
        user = user_response.json()
        if not isinstance(user, dict) or isinstance(user.get('id'), bool) or not isinstance(user.get('id'), int) or user['id'] <= 0 or not isinstance(user.get('login'), str) or not user['login']:
            raise GitHubOAuthError('GitHub returned an invalid identity')
        emails: list[str] = []
        for page in range(1, 11):
            response = await client.get('https://api.github.com/user/emails', headers=headers,
                                        params={'per_page': 100, 'page': page})
            response.raise_for_status()
            entries = response.json()
            if not isinstance(entries, list):
                raise GitHubOAuthError('GitHub returned invalid email data')
            for entry in entries:
                if isinstance(entry, dict) and entry.get('verified') is True and isinstance(entry.get('email'), str):
                    email = entry['email'].strip().lower()
                    if email and email not in emails:
                        emails.append(email)
            if len(entries) < 100:
                break
        else:
            raise GitHubOAuthError('GitHub email list exceeds the supported limit')
        return GitHubIdentity(str(user['id']), user['login'], tuple(emails))
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise GitHubOAuthError('Could not verify the GitHub identity') from exc
