"""Uncalibrated, research-only scoring of detector matches.

These features are descriptive heuristics, not proof of credential validity or
the scoring behavior of BreachTrace's production detector.
"""
from __future__ import annotations

from collections import Counter
import json
import logging
import math
from pathlib import Path
import re

logger = logging.getLogger(__name__)
DEFAULT_WEIGHTS = {'pattern': .35, 'entropy': .25, 'context': .25, 'structural': .15}
WEIGHTS_FILE = Path(__file__).parent / 'weights' / 'learned_weights.json'


def canonical_signals(values):
    """Accept current signal names and earlier research-file aliases."""
    if not isinstance(values, dict):
        return None
    result = {'pattern': values.get('pattern', values.get('pattern_specificity')),
              'entropy': values.get('entropy', values.get('entropy_norm')),
              'context': values.get('context', values.get('context_norm')),
              'structural': values.get('structural', values.get('structural_norm'))}
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1 for value in result.values()):
        return None
    return {key: float(value) for key, value in result.items()}


def load_weights(path: Path = WEIGHTS_FILE):
    try:
        if path.stat().st_size > 16_384:
            raise ValueError('oversized')
        obj = json.loads(path.read_text(encoding='utf-8'))
        values = {'pattern': obj.get('pattern', obj.get('pattern_specificity')),
                  'entropy': obj.get('entropy'), 'context': obj.get('context'), 'structural': obj.get('structural')}
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or abs(v) > 1000 for v in values.values()):
            raise ValueError('invalid weight')
        if not math.isclose(sum(values.values()), 1.0, abs_tol=1e-6):
            raise ValueError('invalid total')
        trained_on = obj.get('trained_on')
        if isinstance(trained_on, bool) or not isinstance(trained_on, int) or trained_on < 1:
            raise ValueError('invalid sample count')
        return values, trained_on
    except (OSError, ValueError, TypeError, AttributeError):
        return dict(DEFAULT_WEIGHTS), None


WEIGHTS, TRAINED_ON = load_weights()
if TRAINED_ON is None:
    logger.info('Scoring weights: defaults (no learned_weights.json found)')
else:
    logger.info('Scoring weights: learned (trained on %s)', TRAINED_ON)


def score_finding(value: str, context: str, line: str, *, weights: dict | None = None) -> dict:
    """Compute normalized signals from a known in-memory candidate and source context."""
    if not isinstance(value, str) or not value:
        raise ValueError('An exact in-memory candidate is required for entropy scoring.')
    counts = Counter(value)
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())
    # Pattern represents a match made by the existing detector, not independent
    # verification; context/structure are observable source properties only.
    lower = context.lower()
    keywords = ('key', 'token', 'secret', 'credential')
    context_signal = sum(word in lower for word in keywords) / len(keywords)
    structural = min(1.0, (0.5 if re.search(r'[:=]', line) else 0.0) +
                     (0.5 if re.search(r'[\'\"]', line) else 0.0))
    signals = {'entropy': min(1.0, entropy / 6.0), 'context': context_signal,
               'structural': structural, 'pattern': 1.0}
    chosen = weights if weights is not None else WEIGHTS
    score = max(0, min(100, round(100 * sum(chosen[name] * signal for name, signal in signals.items()))))
    return {'score': score, 'signals': signals}
