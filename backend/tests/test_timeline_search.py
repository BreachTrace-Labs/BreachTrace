from datetime import datetime, timedelta, timezone

import pytest

from db.crud import create_incident, save_forensic_events
from normalizer.schema import ForensicEvent
from rag.index import index_incident, search
from rag.search import answer
from routers.assistant import SearchRequest


def test_timestamp_search_uses_actual_events_and_preserves_incident_scope(sqlite_factory):
    db = sqlite_factory()
    start = datetime(2026, 10, 1, 14, 23, 30, tzinfo=timezone.utc)
    incidents = [create_incident(db, credential_type="aws_access_key", credential_hint=f"AKIA****{i}",
                                repo_url="https://github.com/team/project", commit_hash=str(i),
                                exposure_start=start) for i in range(2)]
    for incident in incidents:
        save_forensic_events(db, incident.incident_id, [
            ForensicEvent(platform="aws", timestamp=start, api_action="GetObject", source_ip="192.0.2.1",
                          affected_resource="synthetic-bucket/report.csv", raw_data={"sensitive": "never index raw payload"}),
            ForensicEvent(platform="aws", timestamp=start + timedelta(seconds=2), api_action="DeleteObject"),
        ])
        index_incident(db, incident.incident_id)
    result = answer(db, "what happened at 2026-10-01T14:23:30Z", incident_id=incidents[0].incident_id)
    assert result["intent"] == "timeline" and len(result["passages"]) == 1
    passage = result["passages"][0]
    assert passage["source_id"] == incidents[0].incident_id
    assert "GetObject" in passage["text"] and "192.0.2.1" in passage["text"]
    assert "DeleteObject" not in passage["text"] and "never index raw" not in passage["text"]
    assert "selected model" in result["disclaimer"]
    # Retrieval of event details also works without requiring a generated report.
    hits = search(db, "synthetic-bucket/report.csv GetObject", source_ids=[incidents[0].incident_id], include_kb=False)
    assert hits and "event:" in hits[0].chunk.id
    empty = answer(db, "what happened at 2026-10-01T14:24:30Z", incident_id=incidents[0].incident_id)
    assert empty["passages"] == [] and not empty["confident"]


def test_timeline_results_are_bounded_and_expose_truncation(sqlite_factory):
    db = sqlite_factory()
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    incident = create_incident(db, credential_type="aws_access_key", credential_hint="AKIA****bounded",
                               repo_url="local", commit_hash="bounded", exposure_start=start)
    save_forensic_events(db, incident.incident_id, [ForensicEvent(platform="aws", timestamp=start, api_action="GetObject") for _ in range(3)])
    result = answer(db, "events", incident_id=incident.incident_id, k=2, timeline_start=start)
    assert result["truncated"] and len(result["passages"]) == 2


@pytest.mark.parametrize("fields", [
    {"timeline_start": "2026-10-01T00:00:00"},
    {"timeline_end": "2026-10-01T00:00:00Z"},
    {"timeline_start": "2026-10-02T00:00:00Z", "timeline_end": "2026-10-01T00:00:00Z"},
])
def test_invalid_structured_time_ranges_rejected(fields):
    with pytest.raises(ValueError):
        SearchRequest(question="events", **fields)
