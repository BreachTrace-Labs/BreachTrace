import httpx
import pytest

from github_oauth import GitHubOAuthError, fetch_identity


@pytest.mark.asyncio
async def test_fetch_identity_uses_pkce_and_only_verified_emails():
    requests = []
    def handle(request):
        requests.append(request)
        if request.url.host == 'github.com':
            assert b'code_verifier=verifier' in request.content
            return httpx.Response(200, json={'access_token': 'provider-token'})
        assert request.headers['authorization'] == 'Bearer provider-token'
        if request.url.path == '/user':
            return httpx.Response(200, json={'id': 123, 'login': 'example'})
        return httpx.Response(200, json=[{'email': 'USER@example.com', 'verified': True}, {'email': 'other@example.com', 'verified': False}])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await fetch_identity(client, client_id='id', client_secret='secret', code='code', redirect_uri='http://localhost/callback', code_verifier='verifier')
    assert result.github_id == '123'
    assert result.verified_emails == ('user@example.com',)
    assert len(requests) == 3


@pytest.mark.asyncio
async def test_fetch_identity_rejects_provider_failure_without_token_details():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(400, text='sensitive provider response'))) as client:
        with pytest.raises(GitHubOAuthError, match='Could not verify') as error:
            await fetch_identity(client, client_id='id', client_secret='secret', code='code', redirect_uri='http://localhost/callback', code_verifier='verifier')
    assert 'sensitive provider response' not in str(error.value)
