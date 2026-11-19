"""Evaluate reviewed CredData lines against pinned real repositories in memory.

No source text, scanner findings, or credential values are persisted. The
selection deliberately favors repositories with reviewed AWS-ID examples;
results therefore describe this subset, not a representative population.
"""
from collections import defaultdict
import binascii
import csv
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from urllib.parse import urlsplit

import requests

from research.dataset.collector import scan_text
from research.evaluation.metrics import evaluate
from research.evaluation.report import HERE
from research.evaluation.runner import _match, _supported_version

REVISION = '2faad4f03c32c3ff1fe3e7d129fa60913b475ba4'
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_FILE = 1_000_000


def download(url):
    with requests.get(url, timeout=(15, 120), stream=True) as response:
        response.raise_for_status()
        out = io.BytesIO()
        for chunk in response.iter_content(65536):
            out.write(chunk)
            if out.tell() > MAX_ARCHIVE:
                raise ValueError('archive exceeds memory limit')
        return out.getvalue()


def load_metadata(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
        members = [m for m in tf if m.isfile()]
        snapshot = json.load(tf.extractfile(next(m for m in members if m.name.endswith('/snapshot.json'))))
        rows = defaultdict(list)
        for member in members:
            if '/meta/' not in member.name or not member.name.endswith('.csv'):
                continue
            repo_id = member.name.rsplit('/', 1)[-1][:-4]
            with io.TextIOWrapper(tf.extractfile(member), encoding='utf-8-sig') as stream:
                rows[repo_id].extend(csv.DictReader(stream))
    return snapshot, rows


def line_labels(rows):
    """Collapse duplicate reviews; conflicting and unknown labels stay unknown."""
    labels = defaultdict(set)
    for row in rows:
        if row.get('GroundTruth') not in ('T', 'F', 'X'):
            continue
        try:
            start, end = int(row['LineStart']), int(row['LineEnd'])
        except (KeyError, TypeError, ValueError):
            continue
        if start < 1 or end < start or end - start > 1000:
            continue
        for line in range(start, end + 1):
            labels[line].add(row['GroundTruth'])
    return {line: next(iter(values)) for line, values in labels.items() if len(values) == 1 and 'X' not in values}


def external_lines(tool, executable, raw, source):
    """Run offline; use uniquely located raw matches only, never save output."""
    if not executable:
        return None
    cmd = ([executable, '--json', '--no-update', '--no-verification', '--fail-on-scan-errors', 'stdin']
           if tool == 'TruffleHog' else
           [executable, 'stdin', '--no-banner', '--redact', '--report-format', 'json', '--report-path', '-'])
    try:
        result = subprocess.run(cmd, input=raw, capture_output=True, timeout=45, check=False)
        if len(result.stdout) > 16 * 1024 * 1024 or (tool == 'TruffleHog' and result.returncode != 0) or (tool == 'GitLeaks' and result.returncode not in (0, 1)):
            return None
        if tool == 'GitLeaks':
            if result.returncode == 1 and not result.stdout.strip():
                return None
            items = json.loads(result.stdout or b'[]')
            lines = [item.get('StartLine') for item in items]
        else:
            items = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            lines = []
            for item in items:
                value = item.get('Raw')
                if not isinstance(value, str) or not value:
                    return None
                positions = [i for i, line in enumerate(source.splitlines(), 1) if value in line]
                if len(positions) != 1:
                    return None
                lines.append(positions[0])
        return lines if all(isinstance(line, int) and not isinstance(line, bool) and line > 0 for line in lines) else None
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return None


def scan_archive(data, rows, tools=None, scored=None, repo_group=None):
    by_file = defaultdict(list)
    for row in rows:
        by_file[row['FileID']].append(row)
    results, matched, unknown, errors = [], set(), 0, 0
    comparison = {name: [] for name in ('BreachTrace', 'TruffleHog', 'GitLeaks')}
    scope, positive_lines = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
        for member in tf:
            if not member.isfile() or member.size > MAX_FILE or '/' not in member.name:
                continue
            path = member.name.split('/', 1)[1]
            file_id = hashlib.sha256(path.encode()).hexdigest()[:8]
            if file_id not in by_file:
                continue
            # Eight-digit identifiers can theoretically collide; skip both.
            if file_id in matched:
                raise ValueError('ambiguous file identifier')
            matched.add(file_id)
            raw = tf.extractfile(member).read(MAX_FILE + 1)
            if b'\0' in raw:
                errors += 1
                continue
            try:
                source = raw.decode('utf-8-sig')
                diagnostics = []
                findings = scan_text(source, diagnostics=diagnostics)
                if diagnostics:
                    errors += 1
                    continue
            except Exception:
                errors += 1
                continue
            labels = line_labels(by_file[file_id])
            detected = {x.line_number for x in findings if isinstance(x.line_number, int)}
            if scored is not None:
                from research.dataset.scoring_bridge import score_match
                from research.scoring import DEFAULT_WEIGHTS
                by_line = defaultdict(list)
                for match in findings:
                    by_line[match.line_number].append(match)
                for line, matches in by_line.items():
                    if len(matches) != 1 or labels.get(line) not in ('T', 'F'):
                        continue
                    feature = score_match(matches[0], source)
                    if feature.signals:
                        identifier = hashlib.sha256(f'{repo_group}:{file_id}:{line}'.encode()).hexdigest()
                        scored.append({'candidate_id': identifier, 'repository': repo_group,
                                       'source': 'creddata_line_match', 'service': matches[0].credential_type,
                                       'label': 'TP' if labels[line] == 'T' else 'FP',
                                       'score': round(100 * sum(DEFAULT_WEIGHTS[key] * value for key, value in feature.signals.items())), 'signals': feature.signals})
            unknown += sum(line not in labels for line in detected)
            line_count = len(source.splitlines())
            results.extend({'label': 'TP' if label == 'T' else 'FP', 'found': line in detected}
                           for line, label in labels.items() if line <= line_count)
            known_aws = {int(row['LineStart']) for row in by_file[file_id]
                         if row.get('GroundTruth') == 'T' and row.get('PredefinedPattern') == 'aws-id'
                         and row.get('LineStart', '').isdigit() and row.get('LineStart') == row.get('LineEnd')}
            from detector.patterns import AWS_ACCESS_KEY_PATTERN
            source_lines = source.splitlines()
            for line in known_aws:
                if labels.get(line) != 'T' or line > line_count:
                    continue
                keys = {m.group(1) for m in AWS_ACCESS_KEY_PATTERN.finditer(source_lines[line - 1])}
                duplicate = any(getattr(m, 'access_key_id', None) in keys and isinstance(m.line_number, int) and m.line_number < line for m in findings)
                scope.append({'label': 'TP', 'found': line in detected, 'regex_match': bool(keys), 'earlier_duplicate': duplicate})
            positive_lines += sum(label == 'T' and line <= line_count for line, label in labels.items())
            if tools is None:
                continue
            rows_for_match = [{'line_number': line, 'label': 'TP' if label == 'T' else 'FP', 'scope': line in known_aws}
                              for line, label in labels.items() if line <= line_count]
            locations = {'BreachTrace': list(detected)}
            locations.update({name: external_lines(name, executable, raw, source) for name, executable in tools.items()})
            for name, loc in locations.items():
                found, _ = _match(rows_for_match, loc)
                comparison[name].extend({'label': row['label'], 'found': status, 'scope': row['scope']}
                                        for row, status in zip(rows_for_match, found))
    return results, len(matched), unknown, errors, scope, positive_lines, comparison


def run(limit=5, features_only=False):
    print('Downloading pinned CredData metadata...', flush=True)
    url = f'https://codeload.github.com/Samsung/CredData/tar.gz/{REVISION}'
    snapshot, metadata = load_metadata(download(url))
    eligible = sorted(repo for repo, rows in metadata.items()
                      if any(r.get('GroundTruth') == 'T' and r.get('PredefinedPattern') == 'aws-id' for r in rows))
    combined, files, expected_files, unknown, errors, completed = [], 0, 0, 0, 0, []
    failed = 0
    scope_rows, total_positive = [], 0
    comparisons = {name: [] for name in ('BreachTrace', 'TruffleHog', 'GitLeaks')}
    scored = []
    tools = {name: (path if _supported_version(path, major) else None) for name, major in (('TruffleHog', 3), ('GitLeaks', 8)) for path in [shutil.which(name.lower())]}
    for repo in eligible[:limit]:
        matches = [(key, url) for key, url in snapshot.items()
                   if f'{binascii.crc32(bytes.fromhex(key)):08x}' == repo]
        if len(matches) != 1:
            failed += 1
            continue
        key, url = matches[0]
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname != 'github.com' or len(key) != 64:
            failed += 1
            continue
        print(f'Scanning reviewed repository {len(completed) + failed + 1}/{min(limit, len(eligible))}...', flush=True)
        try:
            archive = download(f'https://codeload.github.com{parsed.path}/tar.gz/{key[:40]}')
            found, count, extras, failures, scoped, positives, tool_results = scan_archive(
                archive, metadata[repo], None if features_only else tools, scored if features_only else None, repo)
        except (requests.RequestException, ValueError, tarfile.TarError, OSError):
            failed += 1
            continue
        combined.extend(found); files += count; expected_files += len({r['FileID'] for r in metadata[repo]})
        unknown += extras; errors += failures
        scope_rows.extend(scoped); total_positive += positives
        for name, data in tool_results.items():
            comparisons[name].extend(data)
        completed.append({'repository': parsed.path.lstrip('/'), 'revision': key[:40]})
    if features_only:
        from research.dataset.schema import CORPUS
        path = CORPUS / 'creddata-scored.jsonl'
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        import os
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            for row in scored:
                stream.write(json.dumps(row) + '\n')
        misses = [row for row in scope_rows if not row['found']]
        gap = {'explicit_aws_positives': len(scope_rows), 'explicit_aws_misses': len(misses),
               'misses_with_aws_access_regex_match': sum(row['regex_match'] for row in misses),
               'misses_without_aws_access_regex_match': sum(not row['regex_match'] for row in misses),
               'misses_with_earlier_reported_duplicate': sum(row['earlier_duplicate'] for row in misses),
               'limitation': 'A line-level regex mismatch alone does not establish credential format or out-of-scope status.'}
        (HERE / 'creddata-gap.json').write_text(json.dumps(gap, indent=2) + '\n', encoding='utf-8')
        print(f'Wrote {len(scored)} line-associated scored records; no source values saved.')
        return
    result = {'dataset_revision': REVISION, 'selection': 'first sorted repositories containing a reviewed aws-id true label',
              'repositories': completed, 'repositories_failed': failed, 'matched_files': files,
              'expected_files': expected_files,
              'file_errors': errors, 'unlabeled_detected_lines': unknown, 'metrics': evaluate(combined),
              'explicit_aws_id': {'metrics': evaluate(scope_rows), 'positives': len(scope_rows), 'all_positives': total_positive},
              'comparison': {name: {'available': name == 'BreachTrace' or bool(tools.get(name)),
                                    'metrics': evaluate(rows),
                                    'explicit_aws_id': evaluate([r for r in rows if r['label'] == 'TP' and r['scope']])}
                             for name, rows in comparisons.items()}}
    (HERE / 'creddata-results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"Reviewed lines evaluated: {len(combined)}; repositories: {len(completed)}; unavailable: {failed}; results: research/evaluation/creddata-results.json")
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features-only', action='store_true', help='Export only safe, line-associated research signals')
    args = parser.parse_args()
    try:
        run(features_only=args.features_only)
    except (requests.RequestException, ValueError, tarfile.TarError, OSError):
        print('CredData evaluation unavailable; check network access and archive limits.')
