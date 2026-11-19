"""Train an offline logistic model only when actual labeled signals exist."""
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys

from research.dataset.schema import CORPUS, read_jsonl
from research.scoring import canonical_signals

OUTPUT = Path(__file__).parent / 'learned_weights.json'
FEATURES = ('pattern', 'entropy', 'context', 'structural')


def extract(rows, *, skip_missing=False):
    features, labels, groups = [], [], []
    for row in rows:
        if row.get('label') not in ('TP', 'FP'):
            continue
        signals = canonical_signals(row.get('signals'))
        if signals is None:
            if skip_missing:
                continue
            raise ValueError('Labeled findings lack four valid research signals; collect and label scoreable candidates first.')
        vector = [signals[key] for key in FEATURES]
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1 for value in vector):
            raise ValueError('Each signal must be a finite measured value between 0 and 1.')
        features.append(vector)
        labels.append(1 if row['label'] == 'TP' else 0)
        groups.append(row.get('repository'))
    return features, labels, groups


def main():
    synthetic = [row for row in read_jsonl(CORPUS / 'synthetic-labeled.jsonl') if str(row.get('source', '')).startswith('synthetic_')]
    creddata = [row for row in read_jsonl(CORPUS / 'creddata-scored.jsonl') if row.get('source') == 'creddata_line_match']
    rows = [row for row in read_jsonl(CORPUS / 'labeled.jsonl') + synthetic + creddata if row.get('label') in ('TP', 'FP')]
    if len(rows) < 40:
        print(f'Need >= 40 labeled samples, skipping training (currently {len(rows)}).', file=sys.stderr)
        raise SystemExit(1)
    try:
        x, y, groups = extract(rows, skip_missing=True)
        if len(y) < 40:
            raise ValueError(f'Need >= 40 labeled samples with complete signals, skipping training (currently {len(y)}).')
        if len(y) != len(rows):
            print(f'Excluded {len(rows) - len(y)} labeled findings without complete signals.')
        if min(y.count(0), y.count(1)) < 5:
            raise ValueError('At least five labels of each class are needed for five-fold cross-validation.')
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, cross_val_score
        model = LogisticRegression(C=1.0, max_iter=1000)
        if all(groups) and len(set(groups)) >= 5:
            cv_method = 'stratified grouped five-fold'
            scores = cross_val_score(model, x, y, groups=groups, scoring='f1', cv=StratifiedGroupKFold(5, shuffle=True, random_state=42))
        else:
            cv_method = 'stratified sample-level five-fold; source groups unavailable'
            print('Source groups unavailable; cross-validation may leak related samples.')
            scores = cross_val_score(model, x, y, scoring='f1', cv=StratifiedKFold(5, shuffle=True, random_state=42))
        model.fit(x, y)
        coefficients = model.coef_[0].tolist()
        total = sum(coefficients)
        if abs(total) < 1e-12:
            raise ValueError('Coefficient sum is too close to zero to normalize.')
        output = {key: value / total for key, value in zip(('pattern_specificity', 'entropy', 'context', 'structural'), coefficients)}
        output.update(trained_on=len(y), cv_f1_mean=float(np.mean(scores)), cv_f1_std=float(np.std(scores)),
                      cv_f1_folds=[float(value) for value in scores], timestamp=datetime.now(timezone.utc).isoformat(),
                      logistic_coefficients=coefficients, intercept=float(model.intercept_[0]),
                      synthetic_count=sum(str(row.get('source', '')).startswith('synthetic_') and canonical_signals(row.get('signals')) is not None for row in rows), cv_method=cv_method,
                      limitation='Uncalibrated research heuristic only; normalized signed coefficients are not equivalent to the fitted logistic model. Production detector behavior is unchanged.')
        OUTPUT.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
        print('Cross-validation F1:', ', '.join(f'{value:.3f}' for value in scores))
        print(f'Wrote {OUTPUT}. Detector behavior is unchanged.')
    except ImportError:
        print('Install requirements-research.txt to train.', file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
