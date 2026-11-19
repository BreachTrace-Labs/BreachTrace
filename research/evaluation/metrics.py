"""Metrics over individually labeled and actually evaluated candidates."""
from collections import defaultdict


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def evaluate(rows):
    counts = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'unavailable': 0}
    for row in rows:
        label, found = row.get('label'), row.get('found')
        if label not in ('TP', 'FP'):
            continue
        if not isinstance(found, bool):
            counts['unavailable'] += 1
        elif label == 'TP':
            counts['tp' if found else 'fn'] += 1
        else:
            counts['fp' if found else 'tn'] += 1
    tp, fp, tn, fn = (counts[key] for key in ('tp', 'fp', 'tn', 'fn'))
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return {**counts, 'precision': precision, 'recall': recall,
            'f1': ratio(2 * tp, 2 * tp + fp + fn), 'fpr': ratio(fp, fp + tn),
            'fnr': ratio(fn, tp + fn)}


def per_service(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row.get('service', 'unknown')].append(row)
    return {name: evaluate(items) for name, items in sorted(grouped.items())}
