"""Collect redacted candidate metadata in memory from public GitHub sources.

Network collection is opt-in. No credentials are verified or used, and source
files and their lines are never written to disk.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import time
from urllib.parse import quote, urlsplit

import requests

from .schema import CORPUS, LabeledFinding, append_jsonl, read_jsonl
from .scoring_bridge import score_match

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend'))
from detector.scanner import scan_text  # noqa: E402

QUERIES = ('"sk-proj-" extension:py', '"AKIA" extension:env', '"xoxb-" extension:json',
           '"sk_live_" extension:js', '"AIzaSy" extension:yaml', '"GOCSPX-" extension:env',
           'client_secret extension:env', 'DefaultEndpointsProtocol=https AccountKey')
LANGUAGES = ('Python', 'JavaScript', 'Go', 'Java', 'Ruby')
MAX_FILE = 1_000_000
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_REPO_BYTES = 512 * 1024 * 1024
MAX_REPO_FILES = 10_000
_REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$')
_SHA = re.compile(r'^[0-9a-f]{40,64}$')
_SERVICE = {'aws_access_key': 'aws', 'gcp_service_account': 'google_service_account',
            'firebase_service_account': 'google_service_account', 'azure_storage_connection': 'azure_storage',
            'stripe_secret_key': 'stripe', 'github_pat': 'github', 'slack_token': 'slack',
            'slack_webhook': 'slack', 'sendgrid_api_key': 'sendgrid'}


class GitHub:
    def __init__(self, token: str, delay: float):
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                                     'X-GitHub-Api-Version': '2022-11-28'})
        self.delay = delay

    def get(self, path, **kwargs):
        time.sleep(self.delay)
        result = self.session.get('https://api.github.com' + path, timeout=(10, 45), allow_redirects=False, **kwargs)
        if result.status_code in (403, 429) and result.headers.get('X-RateLimit-Remaining') == '0':
            result.close()
            raise RuntimeError('GitHub rate limit reached. Retry after the reset time.')
        result.raise_for_status()
        return result

    def archive(self, repo: str, revision: str) -> bytes:
        time.sleep(self.delay)
        response = self.session.get(f'https://api.github.com/repos/{repo}/tarball/{revision}',
                                    timeout=(10, 45), allow_redirects=False, stream=True)
        if response.status_code != 302:
            response.close()
            raise RuntimeError('GitHub archive redirect unavailable')
        location = response.headers.get('Location', '')
        parsed = urlsplit(location)
        response.close()
        if parsed.scheme != 'https' or parsed.hostname != 'codeload.github.com' or parsed.username or parsed.password:
            raise RuntimeError('Unexpected GitHub archive host')
        # Never forward the GitHub token to the archive host.
        with requests.get(location, timeout=(10, 45), stream=True, allow_redirects=False) as download:
            download.raise_for_status()
            chunks = io.BytesIO()
            for block in download.iter_content(65536):
                chunks.write(block)
                if chunks.tell() > MAX_ARCHIVE:
                    raise RuntimeError('Compressed archive exceeds limit')
            return chunks.getvalue()


def _repo(name):
    if not isinstance(name, str) or not _REPO.fullmatch(name) or '..' in name or re.search(r'[A-Za-z0-9_+-]{40,}', name):
        raise ValueError('Invalid repository name')
    return name


def _candidate_rows(repo: str, revision: str, path: str, blob_sha: str, data: bytes):
    if len(data) > MAX_FILE or b'\0' in data:
        return []
    # A repository path can itself contain a credential. Do not persist such
    # names or URLs; the source remains entirely in memory.
    from redaction import redact
    if redact(path) != path or scan_text(path) or re.search(r'[A-Za-z0-9_+-]{40,}', path):
        return []
    try:
        source = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return []
    diagnostics = []
    matches = scan_text(source, diagnostics=diagnostics)
    if diagnostics:
        print('A file could not be fully scanned and was excluded.', file=sys.stderr)
        return []
    rows = []
    for index, match in enumerate(matches):
        line = getattr(match, 'line_number', None)
        if not isinstance(line, int) or line < 1:
            continue
        kind = match.credential_type
        safe_hint = str(match.credential_hint or '')[:4] + '***'
        identity = f'{repo}\0{revision}\0{path}\0{blob_sha}\0{line}\0{kind}\0{index}'
        file_url = f'https://github.com/{repo}/blob/{revision}/{quote(path, safe="/")}'
        scored = score_match(match, source)
        rows.append(LabeledFinding(candidate_id=hashlib.sha256(identity.encode()).hexdigest(), file_url=file_url,
            file_sha=blob_sha, repository=repo, revision=revision, path=path, line_number=line,
            match_redacted=safe_hint, service=_SERVICE.get(kind, kind.removesuffix('_api_key')),
            score=scored.score if scored.signals else None, signals=scored.signals,
            context_lines_redacted=['[redacted]'] * 6).to_dict())
    return rows


def _blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def collect(token: str, *, delay: float, max_candidates: int, repos_per_language: int):
    gh = GitHub(token, delay)
    existing = {row['candidate_id'] for row in read_jsonl(CORPUS / 'candidates.jsonl')}
    seen_blobs, services, repo_names = set(), set(), set()
    scanned = findings = search_findings = 0

    def save(repo, revision, path, blob_sha, data):
        nonlocal scanned, findings
        if blob_sha in seen_blobs:
            return 0
        seen_blobs.add(blob_sha)
        scanned += 1
        added = 0
        for row in _candidate_rows(repo, revision, path, blob_sha, data):
            if row['candidate_id'] not in existing:
                append_jsonl(CORPUS / 'candidates.jsonl', row)
                existing.add(row['candidate_id'])
                findings += 1
                added += 1
            services.add(row['service'])
        return added

    for query in QUERIES:
        if search_findings >= max_candidates:
            break
        for page in range(1, 4):
            payload = gh.get('/search/code', params={'q': query, 'per_page': 100, 'page': page}).json()
            items = payload.get('items', [])
            if not items:
                break
            for item in items:
                if search_findings >= max_candidates:
                    break
                repo = _repo(item.get('repository', {}).get('full_name'))
                path, blob_sha = item.get('path', ''), item.get('sha', '')
                if not isinstance(path, str) or not _SHA.fullmatch(blob_sha) or blob_sha in seen_blobs:
                    continue
                metadata = gh.get(f'/repos/{repo}').json()
                branch = metadata.get('default_branch', '')
                revision = gh.get(f'/repos/{repo}/commits/{quote(branch, safe="")}').json().get('sha', '')
                if not _SHA.fullmatch(revision):
                    continue
                content = gh.get(f'/repos/{repo}/contents/{quote(path, safe="/")}', params={'ref': revision}).json()
                if content.get('sha') != blob_sha or content.get('encoding') != 'base64' or content.get('size', 0) > MAX_FILE:
                    continue
                try:
                    data = base64.b64decode(content.get('content', ''), validate=False)
                except (ValueError, TypeError):
                    continue
                if _blob_sha(data) != blob_sha:
                    continue
                search_findings += save(repo, revision, path, blob_sha, data)
                repo_names.add(repo)

    for language in LANGUAGES if repos_per_language else ():
        payload = gh.get('/search/repositories', params={'q': f'stars:>10000 language:{language}',
                         'sort': 'stars', 'per_page': repos_per_language}).json()
        for item in payload.get('items', [])[:repos_per_language]:
            repo = _repo(item.get('full_name'))
            branch = item.get('default_branch', '')
            revision = gh.get(f'/repos/{repo}/commits/{quote(branch, safe="")}').json().get('sha', '')
            if not _SHA.fullmatch(revision):
                continue
            repo_names.add(repo)
            try:
                archive = gh.archive(repo, revision)
                with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tf:
                    total = count = 0
                    for member in tf:
                        if not member.isfile() or member.size > MAX_FILE:
                            continue
                        name = member.name.split('/', 1)
                        if len(name) != 2 or any(part in ('.git', 'node_modules', '.venv', 'vendor') for part in name[1].split('/')):
                            continue
                        total += member.size
                        count += 1
                        if count > MAX_REPO_FILES or total > MAX_REPO_BYTES:
                            print(f'{repo}: scan stopped at file/byte limit', file=sys.stderr)
                            break
                        stream = tf.extractfile(member)
                        if stream:
                            data = stream.read(MAX_FILE + 1)
                            save(repo, revision, name[1], _blob_sha(data), data)
            except (requests.RequestException, tarfile.TarError, RuntimeError, OSError):
                print(f'{repo}: archive unavailable or exceeded limits', file=sys.stderr)
    print(f'{scanned} files scanned, {findings} new findings collected, {len(services)} services covered, {len(repo_names)} repositories sampled')
    print('All findings require manual labels; search results and popular repositories are not ground-truth corpora.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delay', type=float, default=2.0)
    parser.add_argument('--max-candidates', type=int, default=500)
    parser.add_argument('--repos-per-language', type=int, default=10, choices=range(0, 11))
    args = parser.parse_args()
    if args.delay < 1 or args.max_candidates < 1:
        parser.error('Delay must be at least one second and max candidates positive')
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        parser.error('Set GITHUB_TOKEN in your environment; do not paste it into chat.')
    try:
        collect(token, delay=args.delay, max_candidates=args.max_candidates, repos_per_language=args.repos_per_language)
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        print(f'Collection stopped: {type(exc).__name__}. Check authentication, rate limits and GitHub connectivity.', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
