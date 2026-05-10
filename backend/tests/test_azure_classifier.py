# NOTE: These tests are written but not yet runnable.
# They will pass once Shashank completes:
#   - classifier/taxonomy_azure.py  (Day 2-3, Task 2.7) — 70+ Azure operation mappings
#   - classifier/rules.py           (Day 3, Task 3.1)   — Azure platform dispatch + heuristics
#
# TODO(Yash): run pytest tests/test_azure_classifier.py and verify all pass once above are done

from datetime import datetime, timezone

import pytest

from classifier.rules import classify_event, classify_events
from normalizer.schema import ForensicEvent


def _make_azure_event(api_action: str, *, source_ip: str | None = "1.2.3.4") -> ForensicEvent:
    return ForensicEvent(
        platform="azure",
        timestamp=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        source_ip=source_ip,
        success=True,
    )


# ---------------------------------------------------------------------------
# Heuristic fallbacks — /read /write /delete /action suffix rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("api_action", "expected_category", "expected_severity"),
    [
        ("Microsoft.Storage/storageAccounts/read",        "reconnaissance", 1),
        ("Microsoft.Compute/virtualMachines/write",       "resource_abuse", 3),
        ("Microsoft.Compute/virtualMachines/delete",      "resource_abuse", 3),
        ("Microsoft.Logic/workflows/run/action",          "resource_abuse", 3),
        ("Microsoft.Foo/bar/unknownaction",               "reconnaissance", 1),  # fallback
    ],
)
def test_azure_heuristic_suffix_rules(api_action, expected_category, expected_severity):
    event = classify_event(_make_azure_event(api_action))
    assert event.impact_category == expected_category
    assert event.severity_weight == expected_severity


# ---------------------------------------------------------------------------
# Privilege escalation special patterns — override the /write heuristic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "api_action",
    [
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleDefinitions/write",
        "Microsoft.Authorization/policies/write",
    ],
)
def test_azure_priv_esc_patterns_override_write_heuristic(api_action):
    event = classify_event(_make_azure_event(api_action))
    assert event.impact_category == "privilege_escalation"
    assert event.severity_weight == 4


# ---------------------------------------------------------------------------
# Taxonomy lookups — require Shashank to add entries to AZURE_API_TAXONOMY
# ---------------------------------------------------------------------------

def test_keyvault_secrets_read_is_data_access():
    # /read heuristic gives reconnaissance — needs explicit taxonomy entry as data_access
    # so that bulk escalation test below can escalate it to exfiltration
    event = classify_event(_make_azure_event("Microsoft.KeyVault/vaults/secrets/read"))
    assert event.impact_category == "data_access"
    assert event.severity_weight == 2


# ---------------------------------------------------------------------------
# Bulk escalation — same action + same IP >= 5 times → exfiltration
# ---------------------------------------------------------------------------

def test_bulk_azure_data_access_escalates_to_exfiltration():
    # KeyVault secrets read must be data_access initially (taxonomy entry required above)
    events = [
        _make_azure_event("Microsoft.KeyVault/vaults/secrets/read", source_ip="9.9.9.9")
        for _ in range(5)
    ]
    classify_events(events)
    assert all(e.impact_category == "exfiltration" for e in events)
    assert all(e.severity_weight == 4 for e in events)


def test_bulk_escalation_does_not_trigger_below_threshold():
    events = [
        _make_azure_event("Microsoft.KeyVault/vaults/secrets/read", source_ip="9.9.9.9")
        for _ in range(4)
    ]
    classify_events(events)
    assert all(e.impact_category == "data_access" for e in events)


def test_bulk_escalation_scoped_to_same_ip():
    events = [
        _make_azure_event("Microsoft.KeyVault/vaults/secrets/read", source_ip=f"9.9.9.{i}")
        for i in range(1, 6)
    ]
    classify_events(events)
    assert all(e.impact_category == "data_access" for e in events)


def test_bulk_escalation_does_not_apply_to_recon_events():
    # /read heuristic → reconnaissance — bulk should NOT escalate recon to exfiltration
    events = [
        _make_azure_event("Microsoft.Storage/storageAccounts/read", source_ip="9.9.9.9")
        for _ in range(5)
    ]
    classify_events(events)
    assert all(e.impact_category == "reconnaissance" for e in events)


# ---------------------------------------------------------------------------
# Mixed events
# ---------------------------------------------------------------------------

def test_mixed_azure_events_classified_correctly():
    events = [
        _make_azure_event("Microsoft.Storage/storageAccounts/read"),         # reconnaissance
        _make_azure_event("Microsoft.Compute/virtualMachines/write"),        # resource_abuse
        _make_azure_event("Microsoft.Authorization/roleAssignments/write"),  # privilege_escalation
    ]
    classify_events(events)

    assert events[0].impact_category == "reconnaissance"
    assert events[0].severity_weight == 1

    assert events[1].impact_category == "resource_abuse"
    assert events[1].severity_weight == 3

    assert events[2].impact_category == "privilege_escalation"
    assert events[2].severity_weight == 4


def test_classify_event_mutates_and_returns_same_object():
    event = _make_azure_event("Microsoft.Storage/storageAccounts/read")
    result = classify_event(event)
    assert result is event
    assert event.impact_category is not None
