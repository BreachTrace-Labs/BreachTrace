"""Compare detectors against labeled candidates in an existing authorized corpus.

Input files must already exist at ROOT/owner/repo/revision/path and match the
recorded Git blob hash. This runner does not download, copy, or persist source.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from research.dataset.schema import CORPUS, read_jsonl
from research.evaluation.metrics import evaluate, per_service

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'backend'))
from detector.scanner import scan_text  # noqa: E402

RESULTS = Path(__file__).parent / 'results.json'
MAX_FILE = 1_000_000


def _verified_file(root, row):
    try:
        repo, revision, relative = row['repository'], row['revision'], row['path']
        base = (root / repo / revision).resolve(strict=True)
        if not base.is_relative_to(root):
            return None
        path = (base / relative).resolve(strict=True)
        if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > MAX_FILE:
            return None
        data = path.read_bytes()
        digest = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        return path if digest == row['file_sha'] else None
    except (KeyError, OSError, TypeError, ValueError):
        return None


def _scan_breachtrace(path):
    try:
        text = path.read_text(encoding='utf-8-sig')
        diagnostics = []
        matches = scan_text(text, diagnostics=diagnostics)
        if diagnostics or any(not isinstance(m.line_number, int) or isinstance(m.line_number, bool) for m in matches):
            return None
        return [m.line_number for m in matches]
    except (OSError, UnicodeError, ValueError):
        return None


def _external(tool, executable, path):
    if tool == 'TruffleHog':
        command = [executable, '--json', '--no-update', '--no-verification', '--fail-on-scan-errors', 'filesystem', str(path)]
    else:
        command = [executable, 'detect', '--source', str(path), '--no-git', '--report-format', 'json',
                   '--report-path', '/dev/stdout', '--redact']
    try:
        # Captured stdout may contain credential material. It is parsed in
        # memory only, never logged, written to a report or propagated on error.
        result = subprocess.run(command, capture_output=True, timeout=120, check=False)
        if (len(result.stdout) > 16 * 1024 * 1024 or
                (tool == 'TruffleHog' and result.returncode != 0) or
                (tool == 'GitLeaks' and (result.returncode not in (0, 1) or (result.returncode == 1 and not result.stdout.strip())))):
            return None
        if tool == 'TruffleHog':
            output = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            lines = [item.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line') for item in output]
        else:
            output = json.loads(result.stdout or b'[]')
            if not isinstance(output, list):
                return None
            lines = [item.get('StartLine') for item in output]
        if any(not isinstance(line, int) or isinstance(line, bool) or line < 1 for line in lines):
            return None
        return lines
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
        return None


def _supported_version(path, major):
    if not path:
        return False
    try:
        output = subprocess.run([path, '--version'], capture_output=True, timeout=10, check=False)
        match = re.search(rb'\b(?:v)?(\d+)\.\d+', output.stdout + output.stderr)
        return output.returncode == 0 and bool(match) and int(match.group(1)) == major
    except (OSError, subprocess.TimeoutExpired):
        return False


def _match(rows, lines):
    """Match only unambiguous one-to-one line associations; extra output is unknown."""
    if lines is None:
        return [None] * len(rows), 0
    line_counts = Counter(lines)
    unique = sorted(line_counts)
    candidates = [[i for i, row in enumerate(rows) if abs(row['line_number'] - line) <= 2] for line in unique]
    matches = [False] * len(rows)
    unknown = sum(count - 1 for count in line_counts.values())
    for line, choices in zip(unique, candidates):
        if len(choices) != 1:
            unknown += 1
            # Ambiguity is not evidence that any candidate was missed.
            for index in choices:
                matches[index] = None
        elif matches[choices[0]] is True:
            unknown += 1
        elif matches[choices[0]] is not None:
            matches[choices[0]] = True
    return matches, unknown


def run(root: Path, labeled: list[dict]):
    root = root.resolve(strict=True)
    grouped = defaultdict(list)
    seen = set()
    for row in labeled:
        if row.get('label') not in ('TP', 'FP') or row.get('candidate_id') in seen:
            continue
        if not isinstance(row.get('line_number'), int) or row['line_number'] < 1:
            continue
        seen.add(row['candidate_id'])
        grouped[(row.get('repository'), row.get('revision'), row.get('path'), row.get('file_sha'))].append(row)
    trufflehog, gitleaks = shutil.which('trufflehog'), shutil.which('gitleaks')
    tools = {'BreachTrace': None, 'TruffleHog': trufflehog if _supported_version(trufflehog, 3) else None,
             'GitLeaks': gitleaks if _supported_version(gitleaks, 8) else None}
    output = {name: {'rows': [], 'unknown': 0, 'available': name == 'BreachTrace' or bool(executable)}
              for name, executable in tools.items()}
    for rows in grouped.values():
        path = _verified_file(root, rows[0])
        for name, executable in tools.items():
            lines = None if path is None or not output[name]['available'] else (
                _scan_breachtrace(path) if name == 'BreachTrace' else _external(name, executable, path))
            matches, unknown = _match(rows, lines)
            output[name]['unknown'] += unknown
            output[name]['rows'].extend({'candidate_id': row['candidate_id'], 'service': row.get('service', 'unknown'),
                                         'label': row['label'], 'found': found} for row, found in zip(rows, matches))
    for result in output.values():
        result['metrics'] = evaluate(result['rows'])
        result['per_service'] = per_service(result['rows'])
    return {'tools': output, 'labeled_candidates': len(seen), 'files': len(grouped),
            'limitations': 'Metrics are conditional on labeled candidates; unlabelled findings are unknown, and detector-selected samples cannot establish population recall or FPR.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, required=True, help='Existing authorized source files; no files are created here')
    args = parser.parse_args()
    rows = read_jsonl(CORPUS / 'labeled.jsonl')
    if not rows:
        parser.error('No labeled candidates. Run the labeler first.')
    try:
        result = run(args.corpus_root, rows)
    except (OSError, ValueError):
        parser.error('The corpus root is inaccessible.')
    for tool, item in result['tools'].items():
        if not item['available']:
            print(f'{tool}: missing or unsupported version; skipped', file=sys.stderr)
    RESULTS.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    os.chmod(RESULTS, 0o600)
    print(f'Wrote {RESULTS}. No source or tool output was saved.')


if __name__ == '__main__':
    main()
