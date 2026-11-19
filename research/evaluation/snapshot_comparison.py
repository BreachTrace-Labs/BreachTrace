"""Compare scanner output counts on one pinned GitHub snapshot in memory.

Results are descriptive, not precision/recall. Scanner output, repository
contents and candidate values are not saved; provider verification is disabled.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import io
import json
import re
import shutil
import subprocess
import tarfile
import time

from research.dataset.collector import GitHub, _repo, _SHA, scan_text
from detector.repository import EXCLUDED_DIRS
from research.evaluation.report import HERE
from research.evaluation.runner import _supported_version

MAX_FILE = 10 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILES = 200_000


def _external(name, executable, content):
    if name == 'TruffleHog':
        cmd = [executable, '--json', '--no-update', '--no-verification', '--fail-on-scan-errors',
               '--force-skip-archives', '--force-skip-binaries', 'stdin']
    else:
        cmd = [executable, 'stdin', '--no-banner', '--redact', '--report-format', 'json', '--report-path', '-']
    try:
        result = subprocess.run(cmd, input=content, capture_output=True, timeout=45, check=False)
        if len(result.stdout) > 16 * 1024 * 1024:
            return None
        if name == 'TruffleHog':
            if result.returncode != 0:
                return None
            data = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        else:
            if result.returncode not in (0, 1) or (result.returncode == 1 and not result.stdout.strip()):
                return None
            data = json.loads(result.stdout or b'[]')
        return len(data) if isinstance(data, list) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def compare(repo, revision, token):
    repo = _repo(repo)
    if not _SHA.fullmatch(revision):
        raise ValueError('Invalid revision')
    tools = {'TruffleHog': shutil.which('trufflehog'), 'GitLeaks': shutil.which('gitleaks')}
    for name, major in (('TruffleHog', 3), ('GitLeaks', 8)):
        if not _supported_version(tools[name], major):
            tools[name] = None
    counts = {name: {'findings': 0, 'files_with_findings': 0, 'files_failed': 0,
                     'available': name == 'BreachTrace' or bool(tools.get(name)), 'seconds': 0.0}
              for name in ('BreachTrace', 'TruffleHog', 'GitLeaks')}
    families, skipped = Counter(), Counter()
    file_count = total = 0
    data = GitHub(token, delay=1).archive(repo, revision)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            if not member.isfile():
                continue
            parts = member.name.split('/', 1)
            if len(parts) != 2 or any(x in EXCLUDED_DIRS for x in parts[1].split('/')):
                skipped['excluded'] += 1
                continue
            if member.size > MAX_FILE:
                skipped['oversized'] += 1
                continue
            if file_count >= MAX_FILES or total + member.size > MAX_TOTAL:
                skipped['limit_reached'] += 1
                break
            stream = archive.extractfile(member)
            if stream is None:
                skipped['unreadable'] += 1
                continue
            content = stream.read(MAX_FILE + 1)
            if len(content) > MAX_FILE or b'\0' in content:
                skipped['binary_or_oversized'] += 1
                continue
            try:
                source = content.decode('utf-8-sig')
            except UnicodeDecodeError:
                skipped['non_utf8'] += 1
                continue
            file_count += 1
            total += len(content)
            diagnostics = []
            started = time.monotonic()
            try:
                matches = scan_text(source, diagnostics=diagnostics)
                if diagnostics:
                    counts['BreachTrace']['files_failed'] += 1
                else:
                    counts['BreachTrace']['findings'] += len(matches)
                    counts['BreachTrace']['files_with_findings'] += bool(matches)
                    families.update(match.credential_type for match in matches)
            except Exception:
                counts['BreachTrace']['files_failed'] += 1
            counts['BreachTrace']['seconds'] += time.monotonic() - started
            for name, executable in tools.items():
                if not executable:
                    continue
                started = time.monotonic()
                found = _external(name, executable, content)
                counts[name]['seconds'] += time.monotonic() - started
                if found is None:
                    counts[name]['files_failed'] += 1
                else:
                    counts[name]['findings'] += found
                    counts[name]['files_with_findings'] += found > 0
            if file_count % 25 == 0:
                print(f'Compared {file_count} files', flush=True)
    result = {'repository': repo, 'revision': revision, 'measured_at': datetime.now(timezone.utc).isoformat(),
              'text_files': file_count, 'text_bytes': total, 'skipped': dict(skipped), 'tools': counts,
              'breachtrace_types': dict(sorted(families.items())),
              'limitations': ['Raw scanner result counts have different meanings across tools.',
                              'No findings were validated or labeled; precision, recall, F1 and FPR are unavailable.',
                              'Only the selected snapshot and eligible text files were scanned; no Git history.',
                              'The external scanners receive standard input without the original file path; path-dependent rules may behave differently.',
                              'TruffleHog stdin does not provide reliable source line attribution in this setup.',
                              'Subprocess timing includes tool startup for each file.']}
    return result


def write_result(result):
    (HERE / 'snapshot-results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Measured snapshot comparison', '',
             f"Repository: `{result['repository']}` · Revision: `{result['revision']}` · UTC: {result['measured_at']}",
             '', f"Eligible text files compared: **{result['text_files']}** ({result['text_bytes']:,} bytes).",
             f"Skipped: `{json.dumps(result['skipped'], sort_keys=True)}`", '',
             '| Tool | Raw findings | Files with findings | Files unavailable | Tool time (s) |',
             '| --- | ---: | ---: | ---: | ---: |']
    for name, stats in result['tools'].items():
        if stats['available']:
            lines.append(f"| {name} | {stats['findings']} | {stats['files_with_findings']} | {stats['files_failed']} | {stats['seconds']:.2f} |")
        else:
            lines.append(f'| {name} | N/A | N/A | N/A | N/A |')
    lines += ['', '## BreachTrace candidate types', '', '| Candidate type | Findings |', '| --- | ---: |']
    lines.extend(f'| {name} | {count} |' for name, count in result['breachtrace_types'].items())
    lines += ['', '## Interpretation', ''] + [f'- {item}' for item in result['limitations']] + ['']
    (HERE / 'snapshot-results.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    import argparse
    import os
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, help='GitHub owner/repository')
    parser.add_argument('--revision', required=True, help='Pinned commit SHA')
    args = parser.parse_args()
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        parser.error('Set GITHUB_TOKEN in the shell.')
    try:
        result = compare(args.repo, args.revision, token)
        write_result(result)
    except Exception as exc:
        print(f'Comparison failed ({type(exc).__name__}). Check access, network and archive limits.', file=sys.stderr)
        raise SystemExit(1)
    print(f"Compared {result['text_files']} text files. Results: research/evaluation/snapshot-results.md")


if __name__ == '__main__':
    main()
