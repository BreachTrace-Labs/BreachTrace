"""Evaluate an explicitly supplied hypothetical linear scoring model."""
import argparse
import json
import math
from pathlib import Path

from research.dataset.schema import CORPUS, read_jsonl
from research.evaluation.metrics import evaluate
from research.scoring import WEIGHTS
from research.weights.trainer import FEATURES, extract


def run(rows, weights, threshold):
    x, labels, _ = extract(rows, skip_missing=True)
    if not x:
        raise ValueError('No labeled findings have complete research signals.')
    if len(weights) != 4 or any(not math.isfinite(weight) for weight in weights) or not math.isfinite(threshold):
        raise ValueError('Provide exactly four numeric weights.')
    def metric(removed):
        results = [{'label': 'TP' if label else 'FP',
                    'found': 100 * sum(value * weight for index, (value, weight) in enumerate(zip(vector, weights)) if index != removed) >= threshold}
                   for vector, label in zip(x, labels)]
        return evaluate(results)['f1']
    full = metric(None)
    return {'model': 'research linear heuristic; not the deployed BreachTrace detector', 'threshold': threshold,
            'evaluated': len(labels), 'full_f1': full,
            'ablations': [{'signal': name, 'f1': metric(i)} for i, name in enumerate(FEATURES)]}


def run_logistic(rows, coefficients, intercept):
    x, labels, _ = extract(rows, skip_missing=True)
    if not x or len(coefficients) != 4 or not all(math.isfinite(v) for v in [*coefficients, intercept]):
        raise ValueError('Valid fitted logistic coefficients and labeled signals are required.')
    def metric(removed):
        predictions = [{'label': 'TP' if label else 'FP',
                        'found': intercept + sum(value * weight for i, (value, weight) in enumerate(zip(vector, coefficients)) if i != removed) >= 0}
                       for vector, label in zip(x, labels)]
        return evaluate(predictions)['f1']
    return {'model': 'fitted logistic pilot; in-sample ablation, not the deployed detector',
            'evaluated': len(labels), 'full_f1': metric(None),
            'ablations': [{'signal': name, 'f1': metric(i)} for i, name in enumerate(FEATURES)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--weights', nargs=4, type=float, metavar=('PATTERN', 'ENTROPY', 'CONTEXT', 'STRUCTURAL'))
    parser.add_argument('--threshold', type=float, default=50)
    args = parser.parse_args()
    rows = read_jsonl(CORPUS / 'labeled.jsonl') + read_jsonl(CORPUS / 'synthetic-labeled.jsonl') + read_jsonl(CORPUS / 'creddata-scored.jsonl')
    try:
        if not rows:
            raise ValueError('No labeled findings are available.')
        learned = Path(__file__).parents[1] / 'weights' / 'learned_weights.json'
        if args.weights is None and learned.exists():
            model = json.loads(learned.read_text(encoding='utf-8'))
            result = run_logistic(rows, model['logistic_coefficients'], model['intercept'])
        else:
            result = run(rows, args.weights if args.weights is not None else [WEIGHTS[key] for key in FEATURES], args.threshold)
    except ValueError as exc:
        parser.error(str(exc))
    path = Path(__file__).parent / 'ablation.json'
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
