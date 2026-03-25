"""Tests for the rule-based AWS event classifier."""

from classifier.rules import classify_event, classify_all_events
from normalizer.schema import ForensicEvent
from datetime import datetime


def _make_event(api_action: str, source_ip: str = "1.2.3.4") -> ForensicEvent:
    return ForensicEvent(
        timestamp=datetime.utcnow(),
        api_action=api_action,
        event_source="test.amazonaws.com",
        source_ip=source_ip,
    )


class TestSingleClassification:

    def test_list_buckets_is_reconnaissance(self):
        cat, wt = classify_event(_make_event("ListBuckets"))
        assert cat == "reconnaissance"
        assert wt == 1

    def test_get_object_is_data_access(self):
        cat, wt = classify_event(_make_event("GetObject"))
        assert cat == "data_access"
        assert wt == 2

    def test_run_instances_is_resource_abuse(self):
        cat, wt = classify_event(_make_event("RunInstances"))
        assert cat == "resource_abuse"
        assert wt == 3

    def test_create_access_key_is_privilege_escalation(self):
        cat, wt = classify_event(_make_event("CreateAccessKey"))
        assert cat == "privilege_escalation"
        assert wt == 4

    def test_unknown_list_action_falls_back_to_recon(self):
        cat, wt = classify_event(_make_event("ListSomethingNew"))
        assert cat == "reconnaissance"
        assert wt == 1


class TestBulkEscalation:

    def test_five_get_objects_escalates_to_exfiltration(self):
        events = [_make_event("GetObject", "1.2.3.4") for _ in range(5)]
        classified = classify_all_events(events)
        for e in classified:
            assert e.impact_category == "exfiltration"
            assert e.severity_weight == 4

    def test_four_get_objects_stays_data_access(self):
        events = [_make_event("GetObject", "1.2.3.4") for _ in range(4)]
        classified = classify_all_events(events)
        for e in classified:
            assert e.impact_category == "data_access"
