"""Summarize observed score deciles; a score is not automatically a probability."""
from collections import defaultdict
import math
import sys
from pathlib import Path

from research.dataset.schema import CORPUS, read_jsonl


def buckets(rows):
    groups = defaultdict(list)
    for row in rows:
        score, label = row.get('score'), row.get('label')
        if label not in ('TP', 'FP') or isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
            continue
        groups[min(int(score // 10), 9)].append((score, label))
    return [{'score_range': f'{i * 10}–{(i + 1) * 10}',
             'mean_score_fraction': sum(score / 100 for score, _ in items) / len(items) if items else None,
             'actual_tp_rate': sum(label == 'TP' for _, label in items) / len(items) if items else None,
             'count': len(items)} for i in range(10) for items in [groups[i]]]


def main():
    values = buckets(read_jsonl(CORPUS / 'labeled.jsonl') + read_jsonl(CORPUS / 'synthetic-labeled.jsonl') + read_jsonl(CORPUS / 'creddata-scored.jsonl'))
    if not any(item['count'] for item in values):
        print('No labeled numerical scores are available; calibration cannot be computed.', file=sys.stderr)
        raise SystemExit(1)
    print('Score/100 is shown as a score fraction; it is not established to be a calibrated probability.')
    print('score_range | mean_score/100 | actual_tp_rate | count')
    for row in values:
        fmt = lambda value: 'N/A' if value is None else f'{value:.3f}'
        print(f"{row['score_range']} | {fmt(row['mean_score_fraction'])} | {fmt(row['actual_tp_rate'])} | {row['count']}")
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        populated = [row for row in values if row['count']]
        plt.plot([row['mean_score_fraction'] for row in populated], [row['actual_tp_rate'] for row in populated], 'o-')
        plt.plot([0, 1], [0, 1], '--', color='grey')
        plt.xlabel('Mean score / 100'); plt.ylabel('Observed labeled TP fraction')
        plt.tight_layout(); plt.savefig(Path(__file__).parent / 'calibration.png'); plt.close()
    except ImportError:
        print('Matplotlib unavailable; plot skipped.', file=sys.stderr)


if __name__ == '__main__':
    main()
