"""Render measured results without filling unavailable metrics with guesses."""
import csv
from collections import Counter
import json
from pathlib import Path
import re
import sys

from research.dataset.schema import CORPUS, read_jsonl
from research.weights.calibration import buckets

HERE = Path(__file__).parent
SERVICES = ('openai', 'anthropic', 'aws', 'github', 'stripe', 'sendgrid', 'slack',
            'google', 'azure_client_secret', 'azure_storage', 'google_service_account')


def fmt(value):
    return 'N/A' if value is None else f'{value:.3f}'


def safe_name(value):
    return re.sub(r'[^a-zA-Z0-9_ .-]', '', str(value))[:80] or 'unknown'


def render(result, candidates, labels, ablation=None, snapshot=None, creddata=None):
    csv_rows = []
    lines = ['# Research evaluation', '',
             '> Metrics describe only the labeled candidates and hash-verified files actually evaluated. '
             'Detector-selected candidates cannot establish population-level recall, false-positive rate or general detection accuracy. '
             'Unlabeled or ambiguous findings are unknown, not false positives.', '',
             '## Labeled-candidate comparison', '', '| Tool | Precision | Recall | F1 | FPR | Unavailable | Unknown extras |',
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for tool in ('BreachTrace', 'TruffleHog', 'GitLeaks'):
        item = result.get('tools', {}).get(tool, {})
        metrics = item.get('metrics', {}) if item.get('available') else {}
        lines.append(f"| {tool} | {fmt(metrics.get('precision'))} | {fmt(metrics.get('recall'))} | {fmt(metrics.get('f1'))} | {fmt(metrics.get('fpr'))} | {metrics.get('unavailable', 'N/A')} | {item.get('unknown', 'N/A') if item.get('available') else 'N/A'} |")
        for metric in ('precision', 'recall', 'f1', 'fpr', 'fnr', 'tp', 'fp', 'tn', 'fn', 'unavailable'):
            csv_rows.append({'section': 'comparison', 'tool': tool, 'service': '', 'metric': metric, 'value': metrics.get(metric)})
    if isinstance(creddata, dict):
        m = creddata.get('metrics', {})
        lines += ['', '## CredData reviewed-line subset', '',
                  'Independent manual labels from [CredData](https://github.com/Samsung/CredData); '
                  'first sorted repositories containing reviewed AWS-ID positives. Results are line-level, '
                  'not exact credential-span matches, and are not representative of all repositories. '
                  'Unreviewed findings and conflicting/unknown labels are excluded. CredData may label '
                  'test credentials as true; labels do not prove validity or exploitation. The reviewed '
                  'lines span many credential categories, including types BreachTrace may not support; '
                  'this is not an AWS-specific recall measurement. A finding anywhere on a reviewed line '
                  'counts as a match, even if it refers to a different value.', '',
                  f"Dataset revision: `{creddata.get('dataset_revision')}`; repositories: {len(creddata.get('repositories', []))}; "
                  f"files matched: {creddata.get('matched_files', 0)} of {creddata.get('expected_files', 'unknown')} expected; repositories unavailable: {creddata.get('repositories_failed', 0)}; "
                  f"file errors: {creddata.get('file_errors', 0)}; unreviewed detected lines: {creddata.get('unlabeled_detected_lines', 0)}.", '',
                  '| TP | FP | TN | FN | Reviewed-line precision | Reviewed-positive recall | F1 | FPR |',
                  '| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
                  f"| {m.get('tp', 0)} | {m.get('fp', 0)} | {m.get('tn', 0)} | {m.get('fn', 0)} | {fmt(m.get('precision'))} | {fmt(m.get('recall'))} | {fmt(m.get('f1'))} | {fmt(m.get('fpr'))} |", '']
        for metric, value in m.items():
            csv_rows.append({'section': 'creddata_reviewed_lines', 'tool': 'BreachTrace', 'service': '', 'metric': metric, 'value': value})
        scoped = creddata.get('explicit_aws_id', {})
        if scoped:
            sm = scoped.get('metrics', {})
            total = scoped.get('all_positives', 0)
            count = scoped.get('positives', 0)
            lines += ['### Explicit AWS-ID subset', '',
                      'Only lines explicitly annotated `aws-id` are included. Other positive lines have unknown '
                      'or different types; they are not assumed unsupported. This is a narrow lower bound '
                      'on identifiable supported positives, not total service coverage.', '',
                      f"Explicit AWS-ID positive lines: {count}/{total}; exact-line recall: {fmt(sm.get('recall'))} "
                      f"({sm.get('tp', 0)} detected, {sm.get('fn', 0)} missed).", '']
            gap = creddata.get('gap', {})
            if gap:
                lines += [f"Of these misses, {gap.get('misses_with_aws_access_regex_match', 0)} contained an AWS access-key regex match and "
                          f"{gap.get('misses_without_aws_access_regex_match', 0)} did not. "
                          f"{gap.get('misses_with_earlier_reported_duplicate', 0)} had already been reported earlier in the same file. "
                          'A line-level mismatch does not establish that a missed credential is unsupported or justify a pattern change.', '']
        if creddata.get('comparison'):
            lines += ['### Scanner comparison (conservative ±2 line matching)', '',
                      'Ambiguous associations and unavailable file scans are excluded separately for each tool; '
                      'denominators can differ. TruffleHog stdin output is matched only when its raw match '
                      'occurs on exactly one source line. Path-dependent rules are unavailable on stdin. '
                      'These figures cannot establish a precision advantage without comparable denominators.', '',
                      '| Tool | TP | FP | TN | FN | Unavailable | Precision | Recall | AWS-ID recall | F1 | FPR |',
                      '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
            for name, entry in creddata['comparison'].items():
                metrics, aws = entry.get('metrics', {}), entry.get('explicit_aws_id', {})
                lines.append(f"| {name} | {metrics.get('tp', 0)} | {metrics.get('fp', 0)} | {metrics.get('tn', 0)} | {metrics.get('fn', 0)} | {metrics.get('unavailable', 0)} | {fmt(metrics.get('precision'))} | {fmt(metrics.get('recall'))} | {fmt(aws.get('recall'))} | {fmt(metrics.get('f1'))} | {fmt(metrics.get('fpr'))} |")
            lines.append('')
    lines += ['', '## Per-service breakdown — BreachTrace', '', '| Service | Precision | Recall | F1 | FPR | Evaluated |', '| --- | ---: | ---: | ---: | ---: | ---: |']
    service_results = result.get('tools', {}).get('BreachTrace', {}).get('per_service', {})
    for service in sorted(set(SERVICES) | set(service_results)):
        metrics = service_results.get(service, {})
        name = safe_name(service)
        evaluated = sum(metrics.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn'))
        lines.append(f"| {name} | {fmt(metrics.get('precision'))} | {fmt(metrics.get('recall'))} | {fmt(metrics.get('f1'))} | {fmt(metrics.get('fpr'))} | {evaluated} |")
        for metric in ('precision', 'recall', 'f1', 'fpr', 'fnr', 'tp', 'fp', 'tn', 'fn', 'unavailable'):
            csv_rows.append({'section': 'service', 'tool': 'BreachTrace', 'service': name, 'metric': metric, 'value': metrics.get(metric)})
    lines += ['', '## Ablation table', '', 'Ablation is unavailable unless supplied signals and explicit hypothetical-model weights are provided. It does not evaluate the deployed detector. The logistic pilot ablation is in-sample, not held-out evidence.', '',
              '| Signal removed | Full F1 | Ablated F1 | Delta |', '| --- | ---: | ---: | ---: |']
    by_signal = {item['signal']: item.get('f1') for item in (ablation or {}).get('ablations', [])}
    full = (ablation or {}).get('full_f1')
    for key, label in (('entropy', 'No entropy'), ('context', 'No context'), ('structural', 'No structural'), ('pattern', 'No pattern')):
        value = by_signal.get(key)
        delta = value - full if value is not None and full is not None else None
        lines.append(f'| {label} | {fmt(full)} | {fmt(value)} | {fmt(delta)} |')
        for metric, val in (('full_f1', full), ('ablated_f1', value), ('delta', delta)):
            csv_rows.append({'section': 'ablation', 'tool': 'hypothetical', 'service': label, 'metric': metric, 'value': val})
    lines += ['', '## Score calibration', '', 'Score/100 is not established to be a predicted probability. Synthetic labels are assigned by construction and these buckets do not measure real-world calibration.', '',
              '| Score range | Mean score / 100 | Actual TP rate | Count |', '| --- | ---: | ---: | ---: |']
    for bucket in buckets(labels):
        label = bucket['score_range']
        lines.append(f"| {label} | {fmt(bucket['mean_score_fraction'])} | {fmt(bucket['actual_tp_rate'])} | {bucket['count']} |")
        for metric in ('mean_score_fraction', 'actual_tp_rate', 'count'):
            csv_rows.append({'section': 'calibration', 'tool': 'BreachTrace', 'service': label, 'metric': metric, 'value': bucket[metric]})
    labeled = [row for row in labels if row.get('label') in ('TP', 'FP')]
    repos = len({row.get('repository') for row in candidates if row.get('repository')})
    services = len({row.get('service') for row in candidates if row.get('service')})
    lines += ['', '## Dataset summary', '', f'- Candidates recorded: {len(candidates)}',
              f'- Labeled: {len(labeled)} (TP: {sum(row["label"] == "TP" for row in labeled)}, FP: {sum(row["label"] == "FP" for row in labeled)})',
              f'- Synthetic pilot records: {sum(str(row.get("source", "")).startswith("synthetic_") for row in labeled)}; no generated credential values are stored.',
              f'- CredData line-associated scoreable records: {sum(row.get("source") == "creddata_line_match" for row in labeled)}; line-level labels may refer to a different value on the same line.',
              f'- Repositories represented by candidates: {repos} (not the number scanned)', f'- Services represented: {services}',
              f'- Labeled files evaluated or attempted: {result.get("files", 0)}', '']
    lines += ['## Observed candidates by service', '',
              'These are detector candidates, not verified credentials or true-positive counts.', '',
              '| Service | Candidates |', '| --- | ---: |']
    for service, count in sorted(Counter(safe_name(row.get('service', 'unknown')) for row in candidates).items()):
        lines.append(f'| {service} | {count} |')
        csv_rows.append({'section': 'candidate_counts', 'tool': 'BreachTrace', 'service': service,
                         'metric': 'candidates', 'value': count})
    if not candidates:
        lines.append('| None | 0 |')
    lines.append('')
    try:
        weights = json.loads((HERE.parent / 'weights' / 'learned_weights.json').read_text(encoding='utf-8'))
        lines += ['## Scoring model pilot', '',
                  f"Training samples: {weights.get('trained_on')}; synthetic samples: {weights.get('synthetic_count', 'unknown')}. "
                  f"Grouped five-fold synthetic-pilot F1: {fmt(weights.get('cv_f1_mean'))} ± {fmt(weights.get('cv_f1_std'))}.",
                  f"Cross-validation: {weights.get('cv_method', 'unknown')}. "
                  'Synthetic examples use assigned labels and simplified contexts; they do not establish real-world performance. '
                  'The research model does not change production detection. Normalized heuristic weights are not equivalent '
                  'to the logistic model with intercept.', '']
    except (OSError, ValueError):
        pass
    if isinstance(snapshot, dict):
        lines += ['## Measured repository snapshot comparison', '',
                  'These are unverified raw scanner counts from one pinned repository snapshot, not accuracy metrics. '
                  'See [snapshot-results.md](snapshot-results.md) for scope and limitations.', '',
                  f"Text files compared: {int(snapshot.get('text_files', 0))}", '',
                  '| Tool | Raw findings | Files with findings | Files unavailable |',
                  '| --- | ---: | ---: | ---: |']
        for tool in ('BreachTrace', 'TruffleHog', 'GitLeaks'):
            stats = snapshot.get('tools', {}).get(tool, {})
            if stats.get('available'):
                lines.append(f"| {tool} | {int(stats.get('findings', 0))} | {int(stats.get('files_with_findings', 0))} | {int(stats.get('files_failed', 0))} |")
                for metric in ('findings', 'files_with_findings', 'files_failed'):
                    csv_rows.append({'section': 'snapshot_comparison', 'tool': tool, 'service': '',
                                     'metric': metric, 'value': stats.get(metric)})
            else:
                lines.append(f'| {tool} | N/A | N/A | N/A |')
        lines += ['', 'External scanners received text over stdin, without file paths. Tool counts are not interchangeable and may include false positives.', '']
    for metric, value in (('candidates', len(candidates)), ('labeled', len(labeled)), ('candidate_repositories', repos), ('services', services)):
        csv_rows.append({'section': 'dataset', 'tool': '', 'service': '', 'metric': metric, 'value': value})
    return '\n'.join(lines), csv_rows


def load_snapshot():
    path = HERE / 'snapshot-results.json'
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def load_creddata():
    try:
        data = json.loads((HERE / 'creddata-results.json').read_text(encoding='utf-8'))
        try:
            data['gap'] = json.loads((HERE / 'creddata-gap.json').read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            pass
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def main():
    path = HERE / 'results.json'
    result = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'tools': {}, 'files': 0}
    ablation_path = HERE / 'ablation.json'
    ablation = json.loads(ablation_path.read_text(encoding='utf-8')) if ablation_path.exists() else None
    markdown, rows = render(result, read_jsonl(CORPUS / 'candidates.jsonl'), read_jsonl(CORPUS / 'labeled.jsonl') + read_jsonl(CORPUS / 'synthetic-labeled.jsonl') + read_jsonl(CORPUS / 'creddata-scored.jsonl'), ablation, load_snapshot(), load_creddata())
    (HERE / 'results.md').write_text(markdown, encoding='utf-8')
    with (HERE / 'results.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=['section', 'tool', 'service', 'metric', 'value'])
        writer.writeheader(); writer.writerows(rows)
    print('Wrote research/evaluation/results.md and results.csv.')


if __name__ == '__main__':
    main()
