"""Attach research signals to matches without changing detector classes."""
from dataclasses import dataclass, field
import re

from research.scoring import score_finding


@dataclass
class Finding:
    match: object = field(repr=False)
    score: int = 0
    signals: dict[str, float] = field(default_factory=dict)


def _candidate(match, lines):
    for name in ('secret_value', 'access_key_id', 'principal', 'private_key_id'):
        value = getattr(match, name, None)
        if isinstance(value, str) and value:
            return value
    hint = getattr(match, 'credential_hint', '')
    if not isinstance(hint, str) or '****' not in hint:
        return None
    prefix, suffix = hint.split('****', 1)
    if len(prefix) < 4 or len(suffix) < 4:
        return None
    start = max(0, (getattr(match, 'line_number', 1) or 1) - 1)
    end = max(start + 1, getattr(match, 'line_end', None) or start + 1)
    expression = re.compile(re.escape(prefix) + r'[A-Za-z0-9_./+=:\-]{0,512}?' + re.escape(suffix) + r'(?![A-Za-z0-9_])')
    values = {item.group(0) for line in lines[start:end] for item in expression.finditer(line)}
    return next(iter(values)) if len(values) == 1 else None


def score_match(match, source: str) -> Finding:
    finding = Finding(match=match)
    lines = source.splitlines()
    index = (getattr(match, 'line_number', None) or 0) - 1
    if index < 0 or index >= len(lines):
        return finding
    value = _candidate(match, lines)
    if not value:
        return finding
    result = score_finding(value, '\n'.join(lines[max(0, index - 3):index + 4]), lines[index])
    finding.score, finding.signals = result['score'], result['signals']
    return finding
