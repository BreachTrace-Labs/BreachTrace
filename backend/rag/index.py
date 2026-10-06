"""
Search index over knowledge_chunks: storage, incremental updates, hybrid search.

Hybrid = BM25 keyword ranking + embedding cosine similarity, merged with
reciprocal-rank fusion. Everything is in-process and brute force: the index is
a few hundred knowledge-base chunks plus a handful per incident, which a laptop
scans in milliseconds, and it keeps the database free of vector extensions.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass

from sqlalchemy.orm import Session

from db.models import IncidentRecord, KnowledgeChunk
from rag import embedder
from rag.bm25 import BM25
from rag.build_kb import build_kb_chunks

logger = logging.getLogger(__name__)

_RRF_K = 60
_kb_lock = threading.Lock()
_kb_ready = False


@dataclass
class Hit:
    chunk: KnowledgeChunk
    score: float              # fused RRF score, for ordering
    similarity: float | None  # cosine to the query when embeddings exist
    keyword_score: float      # raw BM25


def _hash(title: str, text: str) -> str:
    return hashlib.sha256(f"{title}\n{text}".encode("utf-8")).hexdigest()


def _vector_bytes(vector) -> bytes | None:
    return None if vector is None else vector.astype("float32").tobytes()


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def upsert_chunks(db: Session, chunks: list[dict], *, replace_source: tuple[str, str] | None = None) -> int:
    """
    Insert or update chunks, embedding only those whose content changed.

    ``replace_source=(source_type, source_id)`` also deletes chunks of that
    source that are no longer present (an incident re-indexed after its report
    was rewritten). Returns the number of chunks (re)embedded.
    """
    existing = {}
    if replace_source:
        existing = {
            c.id: c for c in db.query(KnowledgeChunk).filter(
                KnowledgeChunk.source_type == replace_source[0],
                KnowledgeChunk.source_id == replace_source[1],
            )
        }
    else:
        ids = [c["id"] for c in chunks]
        if ids:
            existing = {c.id: c for c in db.query(KnowledgeChunk).filter(KnowledgeChunk.id.in_(ids))}

    changed = [c for c in chunks if getattr(existing.get(c["id"]), "content_hash", None) != _hash(c["title"], c["text"])]
    vectors = embedder.embed([f"{c['title']}\n{c['text']}" for c in changed]) if changed else None

    for i, chunk in enumerate(changed):
        row = existing.get(chunk["id"]) or db.get(KnowledgeChunk, chunk["id"])
        if row is None:
            row = KnowledgeChunk(id=chunk["id"])
            db.add(row)
        row.source_type = chunk["source_type"]
        row.source_id = chunk["source_id"]
        row.title = chunk["title"]
        row.text = chunk["text"]
        row.content_hash = _hash(chunk["title"], chunk["text"])
        row.embedding = _vector_bytes(vectors[i]) if vectors else None

    if replace_source:
        keep = {c["id"] for c in chunks}
        for chunk_id, row in existing.items():
            if chunk_id not in keep:
                db.delete(row)

    db.commit()
    return len(changed)


def ensure_kb(db: Session) -> None:
    """Sync the knowledge base into the index once per process (cheap when unchanged)."""
    global _kb_ready
    if _kb_ready:
        return
    with _kb_lock:
        if _kb_ready:
            return
        chunks = build_kb_chunks()
        updated = upsert_chunks(db, chunks)
        keep = {c["id"] for c in chunks}
        stale = [r for r in db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "kb") if r.id not in keep]
        for row in stale:
            db.delete(row)
        # Chunks stored while embeddings were unavailable get vectors now.
        if embedder.get_embedder() is not None:
            missing = db.query(KnowledgeChunk).filter(KnowledgeChunk.embedding.is_(None)).all()
            vectors = embedder.embed([f"{r.title}\n{r.text}" for r in missing]) if missing else None
            for row, vector in zip(missing, vectors or []):
                row.embedding = _vector_bytes(vector)
        db.commit()
        logger.info("[SEARCH] Knowledge base ready: %d chunks (%d re-indexed, %d removed)", len(chunks), updated, len(stale))
        _kb_ready = True


def incident_chunks(incident: IncidentRecord) -> list[dict]:
    """Searchable passages for one incident: a header plus each report section."""
    platform = incident.platform
    severity = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(incident.overall_severity or 0, "Unknown")
    title = f"{incident.credential_type.replace('_', ' ')} {incident.credential_hint} ({platform})"
    header = (
        f"Incident {incident.incident_id}: a {incident.credential_type.replace('_', ' ')} "
        f"({incident.credential_hint}) on {platform} was exposed in {incident.repo_url} "
        f"at commit {incident.commit_hash or 'unknown'} on {incident.exposure_start:%Y-%m-%d %H:%M} UTC. "
        f"Status: {incident.status}. Severity: {severity}."
        + (f" Financial impact: {incident.financial_impact}." if incident.financial_impact else "")
        + (f" {incident.unavailable_reason}" if incident.unavailable_reason else "")
    )
    chunks = [{
        "id": f"incident:{incident.incident_id}:0",
        "source_type": "incident",
        "source_id": incident.incident_id,
        "title": title,
        "text": header,
    }]
    sections = [s for s in (incident.report_text or "").split("## ") if s.strip()]
    for n, section in enumerate(sections, start=1):
        heading, _, body = section.partition("\n")
        if body.strip():
            chunks.append({
                "id": f"incident:{incident.incident_id}:{n}",
                "source_type": "incident",
                "source_id": incident.incident_id,
                "title": f"{title} — {heading.strip()}",
                "text": body.strip(),
            })
    return chunks


def index_incident(db: Session, incident_id: str) -> None:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        return
    upsert_chunks(db, incident_chunks(incident), replace_source=("incident", incident_id))


def index_incident_in_background(incident_id: str) -> None:
    """BackgroundTask entry point: own session, never raises."""
    from db.database import SessionLocal

    db = SessionLocal()
    try:
        index_incident(db, incident_id)
    except Exception:
        db.rollback()
        logger.exception("[SEARCH] Indexing failed for incident %s", incident_id)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search(
    db: Session,
    query: str,
    *,
    k: int = 5,
    source_type: str | None = None,
    source_ids: list[str] | None = None,
    include_kb: bool = True,
) -> list[Hit]:
    """Hybrid search. ``source_ids`` restricts incident chunks to those incidents."""
    q = db.query(KnowledgeChunk)
    if source_type:
        q = q.filter(KnowledgeChunk.source_type == source_type)
    rows = q.all()
    if source_ids is not None:
        allowed = set(source_ids)
        rows = [
            r for r in rows
            if (r.source_type == "incident" and r.source_id in allowed)
            or (include_kb and r.source_type == "kb")
        ]
    if not rows or not query.strip():
        return []

    keyword = BM25([f"{r.title}\n{r.text}" for r in rows]).scores(query)
    keyword_rank = {i: rank for rank, i in enumerate(sorted(range(len(rows)), key=lambda i: -keyword[i])) if keyword[i] > 0}

    similarity: list[float | None] = [None] * len(rows)
    vector_rank: dict[int, int] = {}
    query_vector = embedder.embed_query(query)
    if query_vector is not None:
        import numpy as np

        for i, row in enumerate(rows):
            if row.embedding:
                similarity[i] = float(np.frombuffer(row.embedding, dtype=np.float32) @ query_vector)
        scored = [i for i in range(len(rows)) if similarity[i] is not None]
        vector_rank = {i: rank for rank, i in enumerate(sorted(scored, key=lambda i: -similarity[i]))}

    hits = []
    for i, row in enumerate(rows):
        fused = sum(1.0 / (_RRF_K + ranks[i] + 1) for ranks in (keyword_rank, vector_rank) if i in ranks)
        if fused:
            hits.append(Hit(row, fused, similarity[i], keyword[i]))
    hits.sort(key=lambda h: -h.score)
    return hits[:k]


def reset_kb_state() -> None:
    """Force ensure_kb() to resync on next call (tests, or after a DB switch)."""
    global _kb_ready
    _kb_ready = False


def stats(db: Session) -> dict:
    total = db.query(KnowledgeChunk).count()
    kb = db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "kb").count()
    embedded = db.query(KnowledgeChunk).filter(KnowledgeChunk.embedding.isnot(None)).count()
    return {"chunks": total, "kb_chunks": kb, "incident_chunks": total - kb, "embedded_chunks": embedded}
