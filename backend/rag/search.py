"""
Answer a natural-language question by retrieval only.

    question → query_parser (rules) → incident filters ──→ matching incidents (ORM)
                                     └→ hybrid search ────→ passages + highlighted sentence

Nothing is generated. Every sentence a user sees is either a database row or a
verbatim passage from the knowledge base or an incident report, with its
source, so the assistant cannot state anything that is not already true.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import exists
from sqlalchemy.orm import Session

from db.models import CREDENTIAL_TYPE_TO_PLATFORM, ForensicEvent, IncidentRecord
from rag import embedder
from rag.bm25 import BM25
from rag.index import ensure_kb, search
from rag.query_parser import ParsedQuery, parse

_MAX_INCIDENTS = 25
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`☐-])")
# Confidence needs semantic support. Calibrated on bge-small against the KB:
# on-topic questions score 0.69-0.89, off-topic ones (pizza, weather) <= 0.45.
# An exact keyword hit on a rare term (CreateAccessKey) is trusted at a lower
# similarity, but a keyword hit alone is not — common words match anything.
_MIN_SIMILARITY = 0.62
_MIN_SIMILARITY_WITH_KEYWORD = 0.48
_STRONG_KEYWORD = 4.0
_SEVERITY_LABELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

EXAMPLE_QUESTIONS = [
    "critical incidents this week",
    "stripe incidents in the last 7 days",
    "which incidents had financial abuse",
    "how do I rotate a Twilio auth token",
    "why is there no timeline for a GitHub token",
    "what does CreateAccessKey mean",
]


def _credential_types(platforms: list[str]) -> list[str]:
    return [ctype for ctype, platform in CREDENTIAL_TYPE_TO_PLATFORM.items() if platform in platforms]


def find_incidents(db: Session, parsed: ParsedQuery) -> list[IncidentRecord]:
    """Parameterised ORM query from validated filters — never generated SQL."""
    q = db.query(IncidentRecord)
    if parsed.incident_ids:
        q = q.filter(IncidentRecord.incident_id.in_(parsed.incident_ids))
    if parsed.platforms:
        q = q.filter(IncidentRecord.credential_type.in_(_credential_types(parsed.platforms)))
    if parsed.severity_min:
        q = q.filter(IncidentRecord.overall_severity >= parsed.severity_min)
    if parsed.date_from:
        q = q.filter(IncidentRecord.exposure_start >= parsed.date_from)
    if parsed.date_to:
        q = q.filter(IncidentRecord.exposure_start < parsed.date_to)
    if parsed.open_only:
        q = q.filter(IncidentRecord.exposure_end.is_(None))
    if parsed.categories:
        q = q.filter(exists().where(
            (ForensicEvent.incident_id == IncidentRecord.incident_id)
            & ForensicEvent.impact_category.in_(parsed.categories)
        ))
    return q.order_by(IncidentRecord.exposure_start.desc()).limit(_MAX_INCIDENTS).all()


def _best_sentence(question: str, text: str) -> str:
    """The sentence of ``text`` that best answers ``question``."""
    sentences = [s.strip() for s in _SENTENCE.split(text) if s.strip()]
    if len(sentences) <= 1:
        return text.strip()
    query_vector = embedder.embed_query(question)
    if query_vector is not None:
        vectors = embedder.embed(sentences)
        scores = [float(v @ query_vector) for v in vectors]
    else:
        scores = BM25(sentences).scores(question)
    return sentences[max(range(len(sentences)), key=lambda i: scores[i])]


def _is_confident(hit) -> bool:
    if hit.similarity is None:  # keyword-only mode: trust a solid BM25 match
        return hit.keyword_score >= _STRONG_KEYWORD
    return hit.similarity >= _MIN_SIMILARITY or (
        hit.similarity >= _MIN_SIMILARITY_WITH_KEYWORD and hit.keyword_score >= _STRONG_KEYWORD
    )


def _incident_row(incident: IncidentRecord) -> dict:
    return {
        "incident_id": incident.incident_id,
        "platform": incident.platform,
        "credential_type": incident.credential_type,
        "credential_hint": incident.credential_hint,
        "repo_url": incident.repo_url,
        "exposure_start": incident.exposure_start.isoformat() if incident.exposure_start else None,
        "status": incident.status,
        "overall_severity": _SEVERITY_LABELS.get(incident.overall_severity or 0),
        "forensic_tier": incident.forensic_tier or 1,
    }


def answer(db: Session, question: str, *, incident_id: str | None = None, k: int = 5) -> dict:
    ensure_kb(db)
    parsed = parse(question, now=datetime.now(timezone.utc))
    if incident_id:
        parsed.incident_ids = [incident_id]

    incidents = find_incidents(db, parsed) if (parsed.wants_incidents or incident_id) else []

    # Scope incident passages to the matched incidents when the question was
    # about incidents; how-to questions search the knowledge base and every
    # incident report.
    if incident_id:
        # Asked from an incident page: that incident's own evidence first, then
        # the playbooks — a generic FAQ must not outrank the user's own report.
        hits = search(db, question, k=3, source_type="incident", source_ids=[incident_id], include_kb=False)
        hits += search(db, question, k=max(1, k - len(hits)), source_type="kb")
    else:
        scope = [i.incident_id for i in incidents] if parsed.wants_incidents else None
        hits = search(db, question, k=k, source_ids=scope)
        if incidents:
            # The user asked about their incidents and some matched: their own
            # passages lead, knowledge-base context follows (stable sort).
            hits.sort(key=lambda h: h.chunk.source_type != "incident")

    passages = []
    for hit in hits:
        chunk = hit.chunk
        passages.append({
            "id": chunk.id,
            "source_type": chunk.source_type,
            "source_id": chunk.source_id,
            "title": chunk.title,
            "text": chunk.text,
            "highlight": _best_sentence(question, chunk.text),
            "similarity": round(hit.similarity, 3) if hit.similarity is not None else None,
        })

    confident = any(_is_confident(h) for h in hits[:3])

    return {
        "question": question,
        "intent": "incidents" if parsed.wants_incidents else "knowledge",
        "filters": parsed.describe(),
        "incidents": [_incident_row(i) for i in incidents],
        "passages": passages if confident or incidents else [],
        "confident": confident,
        "semantic": embedder.get_embedder() is not None,
        "suggestions": [] if (confident or incidents) else EXAMPLE_QUESTIONS,
    }
