import json
from pathlib import Path

from db.models import ExperimentRun, IncidentRecord
from research.ai_demo import _sources, demo_incidents, seed_incidents
from rag.query_parser import parse


def test_demo_fixtures_use_detector_results_and_contain_no_unmasked_keys():
    fixtures = demo_incidents()
    assert {f["platform"] for f in fixtures} == {"openai", "anthropic", "gemini", "deepseek", "sarvam", "groq"}
    serialized = json.dumps(fixtures)
    for _, value, source in _sources():
        assert value not in serialized and source not in serialized
    for fixture in fixtures:
        assert fixture["forensic_tier"] == 2 and fixture["status"] == "complete"
        assert fixture["overall_severity"] is None and fixture["events"] == []
        assert fixture["exposure_end"] is None and fixture["access_key_id"] is None
        assert "fabricated" in fixture["unavailable_reason"]
        assert "Synthetic" in fixture["report_text"]


def test_frontend_and_live_demo_fixtures_match():
    path = Path(__file__).resolve().parents[2] / "client/src/api/aiDemoIncidents.json"
    assert json.loads(path.read_text()) == demo_incidents()


def test_seeding_is_idempotent_and_does_not_add_research_measurements(sqlite_factory):
    with sqlite_factory() as db:
        first = seed_incidents(db)
        assert len(seed_incidents(db)) == 6
        assert db.query(IncidentRecord).count() == 6
        assert db.query(ExperimentRun).count() == 0
        for fixture in first:
            row = db.get(IncidentRecord, fixture["incident_id"])
            assert row.platform == fixture["platform"] and row.forensic_tier == 2


def test_ai_search_filters_match_the_named_provider():
    for name, provider in [("Claude", "anthropic"), ("GPT", "openai"),
                           ("Google Gemini", "gemini"), ("Sarvam AI", "sarvam"),
                           ("DeepSeek", "deepseek"), ("Azure OpenAI", "azureopenai")]:
        query = parse(name + " incidents")
        assert query.platforms == [provider] and query.wants_incidents
