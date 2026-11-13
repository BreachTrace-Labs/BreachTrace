"""Offline checks for the Azure real-incident scenarios (no cloud calls)."""
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from research.scenarios.base import Expect, diff_events
from research.scenarios.runner import load


def test_all_nine_azure_scenarios_registered():
    ids = [c.id for c in load("azure")]
    assert ids == ["AZ-ABUSE-01", "AZ-BULK-01", "AZ-CODE-01", "AZ-COMM-01", "AZ-DATA-01",
                   "AZ-EXFIL-01", "AZ-FIN-01", "AZ-PRIVESC-01", "AZ-RECON-01"]


def test_expectations_match_taxonomy():
    for cls in load("azure"):
        if cls.id == "AZ-BULK-01":
            continue  # asserts the bulk escalation, not the base taxonomy entry
        for e in cls.expected:
            if e.optional:
                continue  # may rely on suffix heuristics
            entry = AZURE_API_TAXONOMY.get(e.api_action)
            assert entry, f"{cls.id}: {e.api_action} missing from taxonomy"
            assert entry["category"] == e.category, (cls.id, e.api_action)
            assert entry["severity"] >= e.min_severity, (cls.id, e.api_action)


def test_diff_events_reports_missing_misclassified_unexpected():
    exp = [Expect("A", "data_access", 4), Expect("B", "exfiltration", 3), Expect("C", "x", 1, optional=True)]
    events = [{"api_action": "A", "impact_category": "data_access", "severity_weight": 4},
              {"api_action": "Z", "impact_category": "x", "severity_weight": 1}]
    d = diff_events(exp, events)
    assert d.matched == 1 and d.missing == ["B"] and d.optional_missing == ["C"] and d.unexpected == ["Z"]
    assert d.ok(blind=False) is False and d.ok(blind=True) is True


def test_bulk_expected_is_exfiltration():
    d = diff_events([Expect("L", "exfiltration", 4)],
                    [{"api_action": "L", "impact_category": "exfiltration", "severity_weight": 4}])
    assert d.ok(False)
