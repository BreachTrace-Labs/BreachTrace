"""
Retrieval evaluation: recall@k on a fixed question set.

    python -m rag.evaluate                 # uses the embedding model if installed
    EMBED_ENABLED=false python -m rag.evaluate   # keyword-only baseline

Each fixture row lists acceptable passage ids; an id ending in `*` matches
every part of a split chunk (taxonomy lists are split by length).
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from rag.index import ensure_kb, search

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "rag_eval.jsonl"


def _matches(chunk_id: str, expected: list[str]) -> bool:
    return any(chunk_id.startswith(e[:-1]) if e.endswith("*") else chunk_id == e for e in expected)


def recall_at_k(db: Session, k: int = 5, fixture: Path = FIXTURE) -> tuple[float, list[dict]]:
    ensure_kb(db)
    rows = [json.loads(line) for line in fixture.open(encoding="utf-8")]
    misses = []
    for row in rows:
        ids = [h.chunk.id for h in search(db, row["question"], k=k, source_type="kb")]
        if not any(_matches(i, row["expected"]) for i in ids):
            misses.append({"question": row["question"], "expected": row["expected"], "got": ids[:3]})
    return 1 - len(misses) / len(rows), misses


def main() -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.orm import sessionmaker

    @compiles(JSONB, "sqlite")
    def _jsonb_as_json(_type, _compiler, **_kw):
        return "JSON"

    from db.models import Base

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    for k in (1, 3, 5):
        recall, misses = recall_at_k(db, k)
        print(f"recall@{k}: {recall:.3f}")
    for miss in misses:
        print("  MISS@5", miss)


if __name__ == "__main__":
    main()
