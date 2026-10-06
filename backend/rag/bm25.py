"""
Okapi BM25 keyword ranking — small enough to own rather than add a dependency.

Security questions are full of exact tokens that embeddings handle poorly:
`charge.succeeded`, `CreateAccessKey`, `AKIA****MPLE`, `45.33.32.156`. The
tokenizer keeps those whole AND indexes their parts, so "charge succeeded",
"charge.succeeded" and "succeeded charges" all meet.
"""
from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9*][a-z0-9_.:/*\-]*[a-z0-9*]|[a-z0-9]")
_SPLIT = re.compile(r"[_.:/\-]+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")
_STOPWORDS = frozenset(
    "a an the and or of to in on for with by is are was were be been it its this that "
    "what which who how why when where do does did can could should would i my me we our "
    "you your from as at about into any all there their them they has have had not no".split()
)


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for token in _TOKEN.findall(text.lower()):
        tokens.append(token)
        parts = [p for p in _SPLIT.split(token) if p]
        if len(parts) > 1:
            tokens.extend(parts)
    # camelCase API names: CreateAccessKey also yields create / access / key.
    for word in re.findall(r"[A-Za-z]+", text):
        pieces = _CAMEL.split(word)
        if len(pieces) > 1:
            tokens.extend(p.lower() for p in pieces)
    return [_stem(t) for t in tokens if t not in _STOPWORDS]


def _stem(token: str) -> str:
    """
    Light suffix folding so inflections meet: charged / charges / charging /
    charge -> "charg", rotating / rotate -> "rotat", keys -> "key". Applied to
    documents and queries alike, so only consistency matters, not linguistics.
    """
    if not token.isalpha() or len(token) <= 3:
        return token
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"
    for suffix in ("ing", "ed", "es", "s"):
        if token.endswith(suffix) and len(token) - len(suffix) >= 3 and not token.endswith(("ss", "us", "is")):
            token = token[: -len(suffix)]
            break
    return token[:-1] if token.endswith("e") and len(token) > 4 else token


class BM25:
    def __init__(self, documents: list[str], *, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.docs = [Counter(tokenize(d)) for d in documents]
        self.lengths = [sum(c.values()) for c in self.docs]
        self.avg_length = (sum(self.lengths) / len(self.lengths)) if self.lengths else 0.0
        df: Counter[str] = Counter()
        for counts in self.docs:
            df.update(counts.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: str) -> list[float]:
        terms = set(tokenize(query))
        out = []
        for counts, length in zip(self.docs, self.lengths):
            score = 0.0
            for term in terms:
                tf = counts.get(term)
                if not tf:
                    continue
                norm = tf + self.k1 * (1 - self.b + self.b * length / (self.avg_length or 1))
                score += self.idf.get(term, 0.0) * tf * (self.k1 + 1) / norm
            out.append(score)
        return out
