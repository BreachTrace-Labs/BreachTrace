"""Run available research steps without fabricating missing data."""
from __future__ import annotations

import argparse
import csv
import logging
import os
from pathlib import Path
import sys

logging.basicConfig(level=logging.INFO, format='%(message)s')
from research import scoring  # noqa: F401, E402 — log the active research weights at startup
from research.dataset.schema import CORPUS, read_jsonl
from research.evaluation import report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, help='Existing authorized source corpus for scanner comparison')
    parser.add_argument('--interactive', action='store_true', help='Allow interactive manual labeling')
    parser.add_argument('--benchmark', action='store_true', help='Run the public CredData comparison and synthetic pilot (network required)')
    args = parser.parse_args()
    skipped = []
    if args.benchmark:
        from research.dataset.synthetic import generate
        from research.evaluation.creddata import run as run_creddata
        print('Step 1: generate the explicitly synthetic pilot.', flush=True)
        generate()
        for label, features_only in (('Step 2: compare scanners on CredData.', False),
                                      ('Step 3: extract safe line-associated CredData features.', True)):
            print(label, flush=True)
            try:
                run_creddata(features_only=features_only)
            except Exception as exc:
                print(f'CredData step unavailable ({type(exc).__name__}); continuing.')
                skipped.append('CredData step unavailable; check connectivity and archive limits.')
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print('GITHUB_TOKEN not set, skipping collection')
        skipped.append('Collection was skipped in this run because GITHUB_TOKEN was not set; existing candidates, if any, are retained.')
    else:
        from research.dataset.collector import collect
        try:
            collect(token, delay=2, max_candidates=500, repos_per_language=10)
        except Exception as exc:
            print(f'Collection unavailable ({type(exc).__name__}); continuing.')
            skipped.append('Collection failed; check authentication, rate limits and connectivity.')
    try:
        candidates = read_jsonl(CORPUS / 'candidates.jsonl')
        if not candidates:
            print('No candidates found, skipping labeling')
            skipped.append('Labeling: no candidates found.')
        elif args.interactive and sys.stdin.isatty():
            from research.dataset.labeler import main as label
            label()
        else:
            print('Manual labeling skipped; use --interactive in a terminal.')
            skipped.append('Labeling: manual review not requested or no terminal available.')
        labels = read_jsonl(CORPUS / 'labeled.jsonl')
    except (OSError, ValueError):
        print('Corpus files could not be read; skipping labeling and training.')
        skipped.append('Corpus files were inaccessible or invalid.')
        candidates, labels = [], []
    labeled = [row for row in labels if row.get('label') in ('TP', 'FP')]
    training_labels = labeled + read_jsonl(CORPUS / 'synthetic-labeled.jsonl') + read_jsonl(CORPUS / 'creddata-scored.jsonl')
    if len(training_labels) < 40:
        print('Need >= 40 labeled samples, skipping training')
        skipped.append(f'Training: {len(training_labels)} labeled samples; at least 40 required.')
    else:
        from research.weights.trainer import main as train
        try:
            train()
        except SystemExit:
            print('Training unavailable; check feature coverage and label balance.')
            skipped.append('Training: missing valid signals, class balance or dependencies.')
    if args.benchmark:
        print('Step 4: ablation and calibration.', flush=True)
        try:
            from research.evaluation.ablation import run_logistic
            from research.weights.calibration import buckets
            import json
            model = json.loads((report.HERE.parent / 'weights' / 'learned_weights.json').read_text())
            ablation_result = run_logistic(training_labels, model['logistic_coefficients'], model['intercept'])
            (report.HERE / 'ablation.json').write_text(json.dumps(ablation_result, indent=2) + '\n')
            print(f"Calibration: {sum(row['count'] for row in buckets(training_labels))} scored records; see report.")
        except (OSError, ValueError, KeyError, TypeError):
            print('Ablation or calibration unavailable; continuing.')
            skipped.append('Ablation unavailable: model or valid signals missing.')
    result = {'tools': {}, 'files': 0}
    if labeled and args.corpus_root:
        from research.evaluation.runner import run
        try:
            result = run(args.corpus_root, labeled)
            for name, item in result['tools'].items():
                if not item['available']:
                    print(f'{name} unavailable, comparison skipped')
                    skipped.append(f'{name}: missing or unsupported version.')
        except (OSError, ValueError):
            print('Corpus root unavailable, skipping scanner comparison')
            skipped.append('Comparison: corpus root unavailable.')
    else:
        print('No labeled corpus files supplied, skipping scanner comparison')
        skipped.append('Comparison: labeled candidates and an authorized --corpus-root are required.')
    ablation_path = report.HERE / 'ablation.json'
    import json
    ablation = json.loads(ablation_path.read_text()) if ablation_path.exists() else None
    markdown, rows = report.render(result, candidates, training_labels, ablation=ablation, snapshot=report.load_snapshot(), creddata=report.load_creddata())
    markdown += '\n## Skipped steps\n\n' + ('\n'.join(f'- {reason}' for reason in skipped) if skipped else '- None.') + '\n'
    output = report.HERE / 'results.md'
    output.write_text(markdown, encoding='utf-8')
    with (report.HERE / 'results.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=['section', 'tool', 'service', 'metric', 'value'])
        writer.writeheader(); writer.writerows(rows)
    print('Results written to research/evaluation/results.md')


if __name__ == '__main__':
    main()
