"""
Retrieval-only natural-language search: query parsing, the index, incident
filtering, and the HTTP API.

Embeddings are disabled in the test environment (conftest), so these run the
keyword path deterministically; the recall bar here is the keyword-only one.
`python -m rag.evaluate` measures the hybrid number with the real model.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from db.crud import create_incident, save_forensic_events
from db.models import KnowledgeChunk
from normalizer.schema import ForensicEvent
from rag.bm25 import BM25, tokenize
from rag.evaluate import recall_at_k
from rag.index import index_incident, search
from rag.query_parser import parse
from rag.search import answer

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)  # a Wednesday


# ==========================================================================
# Query parser
# ==========================================================================

@pytest.mark.parametrize("question, expected", [
    ("critical incidents this week", {"severity_min": 4, "wants": True}),
    ("stripe incidents in the last 7 days", {"platforms": ["stripe"], "wants": True}),
    ("show me high severity aws leaks", {"platforms": ["aws"], "severity_min": 3, "wants": True}),
    ("which incidents had financial abuse", {"categories": ["financial_abuse"], "wants": True}),
    ("open incidents", {"open_only": True, "wants": True}),
    ("leaks since 2026-10-01", {"wants": True}),
    ("google cloud and twilio incidents", {"platforms": ["gcp", "twilio"], "wants": True}),
    ("how do I rotate a twilio auth token", {"platforms": ["twilio"], "wants": False}),
    ("why is there no timeline for a github token", {"platforms": ["github"], "wants": False}),
    ("sms pumping protection", {"categories": ["communication_abuse"], "wants": False}),
    ("what does CreateAccessKey mean", {"platforms": [], "wants": False}),
    ("postgres connection string leaked", {"platforms": ["db"], "wants": True}),
])
def test_parser(question, expected):
    parsed = parse(question, now=NOW)
    assert parsed.wants_incidents is expected["wants"]
    for field in ("platforms", "severity_min", "categories", "open_only"):
        if field in expected:
            assert getattr(parsed, field) == expected[field], field


@pytest.mark.parametrize("question, start, end", [
    ("incidents today", NOW.replace(hour=0), None),
    ("incidents yesterday", NOW.replace(hour=0) - timedelta(days=1), NOW.replace(hour=0)),
    ("incidents this week", NOW.replace(hour=0) - timedelta(days=2), None),
    ("incidents last week", NOW.replace(hour=0) - timedelta(days=9), NOW.replace(hour=0) - timedelta(days=2)),
    ("incidents in the past 3 days", NOW - timedelta(days=3), None),
    ("incidents on 2026-10-01", datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 2, tzinfo=timezone.utc)),
    ("incidents between 2026-09-01 and 2026-09-30",
     datetime(2026, 9, 1, tzinfo=timezone.utc), datetime(2026, 10, 1, tzinfo=timezone.utc)),
])
def test_parser_dates(question, start, end):
    parsed = parse(question, now=NOW)
    assert (parsed.date_from, parsed.date_to) == (start, end)


def test_parser_never_emits_unknown_values():
    parsed = parse("incidents on digitalocean with banana severity", now=NOW)
    assert parsed.platforms == [] and parsed.severity_min is None and parsed.categories == []


# ==========================================================================
# BM25
# ==========================================================================

def test_tokenizer_keeps_exact_tokens_and_parts():
    tokens = tokenize("CreateAccessKey charge.succeeded 45.33.32.156 charges")
    # Exact tokens survive whole; their parts are indexed too (suffix-folded).
    for expected in ("createaccesskey", "access", "key", "charge.succeeded", "45.33.32.156"):
        assert expected in tokens
    assert set(tokenize("create")) <= set(tokens)
    # Inflections meet: "charges" and the "charge" inside charge.succeeded fold together.
    assert tokens.count(tokenize("charge")[0]) == 2
    assert tokenize("charged") == tokenize("charging") == tokenize("charge")


def test_bm25_ranks_the_relevant_document_first():
    docs = ["Roll a Stripe key in the Dashboard", "Rotate a Twilio Auth Token", "Delete an AWS access key"]
    scores = BM25(docs).scores("rotating twilio tokens")
    assert scores.index(max(scores)) == 1


# ==========================================================================
# Index + retrieval quality
# ==========================================================================

def test_keyword_recall_meets_bar(sqlite_factory):
    """Keyword-only floor; hybrid (with embeddings) measured 0.977 recall@5."""
    recall, misses = recall_at_k(sqlite_factory(), k=5)
    assert recall >= 0.85, misses


def test_kb_reindex_is_incremental(sqlite_factory):
    from rag import index

    db = sqlite_factory()
    index.ensure_kb(db)
    first = db.query(KnowledgeChunk).count()
    index.reset_kb_state()
    from rag.build_kb import build_kb_chunks

    assert index.upsert_chunks(db, build_kb_chunks()) == 0  # unchanged content: nothing re-embedded
    assert db.query(KnowledgeChunk).count() == first


def _incident(db, ctype, hint, severity, started, report, category=None):
    incident = create_incident(
        db, credential_type=ctype, credential_hint=hint, repo_url="https://github.com/demo/r",
        commit_hash="abc", exposure_start=started, principal_id=hint,
    )
    incident.overall_severity = severity
    incident.report_text = report
    incident.status = "complete"
    db.commit()
    if category:
        event = ForensicEvent(platform="stripe", timestamp=started, api_action="charge.succeeded",
                              impact_category=category, severity_weight=4)
        save_forensic_events(db, incident.incident_id, [event])
    index_incident(db, incident.incident_id)
    return incident


@pytest.fixture
def populated(sqlite_factory):
    db = sqlite_factory()
    recent = datetime.now(timezone.utc) - timedelta(hours=2)
    stripe = _incident(db, "stripe_secret_key", "sk_live_****abcd", 4, recent,
                       "## Executive Summary\n\nA fraudulent charge of 412.50 USD was created on ch_1.\n",
                       category="financial_abuse")
    aws = _incident(db, "aws_access_key", "AKIA****MPLE", 1, recent - timedelta(days=40),
                    "## Executive Summary\n\nThe key only listed S3 buckets.\n")
    return db, stripe, aws


def test_incident_query_filters(populated):
    db, stripe, aws = populated
    ids = lambda q: {i["incident_id"] for i in answer(db, q)["incidents"]}  # noqa: E731
    assert ids("stripe incidents") == {stripe.incident_id}
    assert ids("critical incidents") == {stripe.incident_id}
    assert ids("incidents with financial abuse") == {stripe.incident_id}
    assert ids("incidents in the last 7 days") == {stripe.incident_id}
    assert ids("aws leaks") == {aws.incident_id}


def test_incident_passages_are_scoped_to_matched_incidents(populated):
    db, stripe, aws = populated
    result = answer(db, "stripe incidents with a fraudulent charge")
    incident_passages = [p for p in result["passages"] if p["source_type"] == "incident"]
    assert incident_passages and all(p["source_id"] == stripe.incident_id for p in incident_passages)


def test_question_about_one_incident(populated):
    db, stripe, _ = populated
    result = answer(db, "what was charged", incident_id=stripe.incident_id)
    assert [i["incident_id"] for i in result["incidents"]] == [stripe.incident_id]
    top = result["passages"][0]
    assert top["source_id"] == stripe.incident_id and "412.50" in top["highlight"]


def test_how_to_question_returns_knowledge(populated):
    db, *_ = populated
    result = answer(db, "how do I rotate a Twilio auth token")
    assert result["intent"] == "knowledge" and result["incidents"] == []
    assert result["passages"][0]["id"].startswith("kb:playbooks_saas-how-to-rotate")


def test_off_topic_question_is_not_answered(populated):
    db, *_ = populated
    result = answer(db, "zebra quantum lasagne")
    assert result["passages"] == [] and result["confident"] is False and result["suggestions"]


def test_hits_carry_no_full_secrets(populated):
    db, *_ = populated
    for hit in search(db, "stripe key", k=20):
        assert "sk_live_" not in hit.chunk.text.replace("sk_live_****", "")


# ==========================================================================
# API
# ==========================================================================

def test_assistant_api(sqlite_factory, monkeypatch):
    from db.database import get_db
    from routers import assistant

    app = FastAPI()
    app.include_router(assistant.router)

    def _db():
        db = sqlite_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _db
    client = TestClient(app)

    response = client.post("/assistant/search", json={"question": "how do I roll a stripe key"})
    assert response.status_code == 200
    body = response.json()
    assert body["passages"][0]["title"].lower().startswith("how to roll a leaked stripe")
    assert set(body) >= {"incidents", "passages", "confident", "filters", "intent", "suggestions"}

    assert client.post("/assistant/search", json={"question": "x"}).status_code == 422

    status = client.get("/assistant/status").json()
    assert status["index"]["kb_chunks"] > 50
    assert status["report_model"]["installed"] is False  # disabled in tests
