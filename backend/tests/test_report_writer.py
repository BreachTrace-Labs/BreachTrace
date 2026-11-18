"""
The report-writing path: fact sheet → (template | model) prose → validator →
markdown with a deterministic checklist.

The validator is the safety net that lets a very small model write reports, so
most tests here pin what it must reject — and, just as important, that it does
not reject correct prose (a validator that cries wolf would silently force
every report back to the template).
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

import pytest

import pipeline
from classifier.rules import classify_events
from db.models import IncidentRecord
from normalizer.schema import ForensicEvent
from reporter import writers
from reporter.compose import deterministic_sections, render_report
from reporter.facts import build_fact_sheet, humanize_duration
from reporter.prompt import build_messages, parse_sections
from reporter.remediation import build_remediation
from reporter.validate import validate_sections
from research.report_distill import synth_incident
from scorer.severity import score_incident

T0 = datetime(2026, 10, 1, 14, 23, tzinfo=timezone.utc)


def _ev(platform, action, source="x", resource=None, ip=None, dt=0, raw=None, success=True):
    return ForensicEvent(
        platform=platform, timestamp=T0 + timedelta(seconds=dt), api_action=action,
        event_source=source, affected_resource=resource, source_ip=ip,
        raw_data=raw or {}, success=success,
    )


def _facts(platform, events, seconds=1351):
    classify_events(events)
    return build_fact_sheet(
        events, platform=platform, overall_severity=score_incident(events),
        exposure_duration_seconds=seconds, credential_type="aws_access_key",
        credential_hint="AKIA****MPLE",
    )


@pytest.fixture
def aws_facts():
    return _facts("aws", [
        _ev("aws", "ListBuckets", "s3.amazonaws.com", ip="45.33.32.156"),
        _ev("aws", "GetObject", "s3.amazonaws.com", "prod-backups/users_2026.csv", "45.33.32.156", 30),
        _ev("aws", "RunInstances", "ec2.amazonaws.com", "i-0abc123", "45.33.32.156", 90),
        _ev("aws", "CreateAccessKey", "iam.amazonaws.com", "root", "45.33.32.156", 400),
    ])


def _sections(summary, narrative=("Step one.",), impact="Impact."):
    return {"executive_summary": summary, "narrative": list(narrative), "business_impact": impact}


@pytest.mark.parametrize('platform', ['aws', 'gcp', 'azure', 'stripe', 'twilio'])
def test_template_does_not_infer_public_exposure_or_confirm_rotation(platform):
    facts = _facts(platform, [])
    report = render_report(facts, deterministic_sections(facts))
    assert 'estimated exposure start' in report
    assert 'rotation is not confirmed' in report
    assert 'public repository' not in report
    assert 'was exposed in' not in report


def test_model_prompt_excludes_unverified_exposure_claims(aws_facts):
    system_prompt = build_messages(aws_facts)[0]['content']
    assert 'do not claim the repository was public' in system_prompt
    assert 'account-level or application-level activity' in system_prompt


# ==========================================================================
# Fact sheet
# ==========================================================================

def test_fact_sheet_ranks_worst_actions_first(aws_facts):
    assert aws_facts["actions"][0]["action"] == "CreateAccessKey"
    assert next(iter(aws_facts["categories"])) == "privilege_escalation"
    assert aws_facts["severity"] == "Critical"
    assert aws_facts["source_ips"] == ["45.33.32.156"]


def test_fact_sheet_stays_compact_for_bulk_incidents():
    """5,000 Twilio messages must not become 5,000 lines in the prompt."""
    events = [_ev("twilio", "message.sent", resource=f"+1555{i:07d}", dt=i) for i in range(5000)]
    facts = _facts("twilio", events)
    assert facts["event_count"] == 5000
    assert len(json.dumps(facts)) < 4000


@pytest.mark.parametrize("seconds, text", [
    (45, "45 seconds"), (1351, "22 minutes"), (3600, "1 hour"), (90_000, "1 day 1 hour"),
])
def test_humanize_duration(seconds, text):
    assert humanize_duration(seconds) == text


# ==========================================================================
# Validator — what it must reject
# ==========================================================================

@pytest.mark.parametrize("bad, reason", [
    ("The attacker connected from 203.0.113.9.", "IP address 203.0.113.9"),
    ("They downloaded payroll_2026.xlsx from the bucket.", "payroll_2026.xlsx"),
    ("They launched i-0deadbeef9 in us-west-2.", "i-0deadbeef9"),
    ("The attacker caused $4,200.00 of damage.", "amount"),
    ("The key was used to make 47 API calls.", "count"),
    ("Use AKIAIOSFODNN7EXAMPLE to verify.", "credential-shaped"),
    ("Review the Activity Log for the resource group.", "azure vocabulary"),
])
def test_validator_rejects_invented_or_wrong_content(aws_facts, bad, reason):
    violations = validate_sections(_sections(bad), aws_facts)
    assert any(reason in v for v in violations), violations


def test_validator_rejects_unused_claim_on_empty_incident():
    facts = _facts("stripe", [])
    violations = validate_sections(_sections("The key was never used."), facts)
    assert any("unused" in v for v in violations)


def test_validator_accepts_the_hedged_statement():
    facts = _facts("stripe", [])
    text = "No activity was recorded. This does not prove the key went unused."
    assert validate_sections(_sections(text), facts) == []


def test_validator_accepts_grounded_paraphrase(aws_facts):
    sections = _sections(
        "An AWS access key was public for 22 minutes and was used from 45.33.32.156 "
        "to create a new access key for root and launch instance i-0abc123.",
        ["It first listed buckets, then read prod-backups/users_2026.csv."],
        "Severity is Critical. The instance costs about $0.01 per hour.",
    )
    assert validate_sections(sections, aws_facts) == []


def test_template_passes_validator_on_varied_incidents():
    """The validator must not reject correct prose: zero false alarms on the template."""
    rng = random.Random(3)
    for i in range(150):
        facts = synth_incident(rng, i)
        assert validate_sections(deterministic_sections(facts), facts) == [], facts["platform"]


# ==========================================================================
# Remediation + markdown
# ==========================================================================

@pytest.mark.parametrize("platform, command", [
    ("aws", "aws iam delete-access-key"),
    ("gcp", "gcloud iam service-accounts keys delete"),
    ("azure", "az ad app credential delete"),
    ("stripe", "Roll key"),
    ("twilio", "secondary Auth Token"),
])
def test_remediation_starts_with_the_platform_revoke(platform, command):
    steps = build_remediation({"platform": platform, "categories": {}, "actions": []})
    assert steps[0].startswith("☐ Revoke") and command in steps[0]
    assert all(s.startswith("☐ ") for s in steps)


def test_remediation_adds_category_specific_steps(aws_facts):
    steps = " ".join(build_remediation(aws_facts))
    assert "Delete any IAM access keys" in steps          # privilege escalation
    assert "i-0abc123" in steps                          # resource abuse, named
    assert "45.33.32.156" in steps


def test_rendered_report_keeps_checklist_parseable(aws_facts):
    text = render_report(aws_facts, deterministic_sections(aws_facts))
    steps = pipeline._extract_remediation_steps(text)
    assert steps == build_remediation(aws_facts)
    for heading in ("## Executive Summary", "## What Happened", "## Business Impact", "## Remediation Checklist"):
        assert heading in text


def test_narrative_is_chronological(aws_facts):
    narrative = deterministic_sections(aws_facts)["narrative"]
    assert narrative[0].startswith("2026-10-01 14:23:00") and "CreateAccessKey" in narrative[-1]


# ==========================================================================
# Prompt contract
# ==========================================================================

def test_prompt_carries_facts_and_feedback(aws_facts):
    messages = build_messages(aws_facts, ["IP address 1.2.3.4 is not in the facts"])
    assert messages[0]["role"] == "system"
    assert "45.33.32.156" in messages[1]["content"]
    assert "1.2.3.4 is not in the facts" in messages[1]["content"]


@pytest.mark.parametrize("raw, ok", [
    ('{"executive_summary": "S", "narrative": ["a"], "business_impact": "I"}', True),
    ('```json\n{"executive_summary": "S", "narrative": ["a"], "business_impact": "I"}\n```', True),
    ('{"executive_summary": "S", "narrative": "one step", "business_impact": "I"}', True),
    ('{"executive_summary": "", "narrative": ["a"], "business_impact": "I"}', False),
    ('{"executive_summary": "S", "business_impact": "I"}', False),
    ('{"executive_summary": "S", "narrative": ["a"], "business_im', False),
    ("not json at all", False),
])
def test_parse_sections(raw, ok):
    assert (parse_sections(raw) is not None) is ok


# ==========================================================================
# Validated upgrade
# ==========================================================================

def test_writer_gets_one_corrective_retry(aws_facts):
    calls = []

    def writer(facts, feedback=None):
        calls.append(feedback)
        if feedback is None:
            return _sections("Used from 203.0.113.9.")
        return _sections("Used from 45.33.32.156.")

    sections, violations = writers.write_validated(writer, aws_facts)
    assert sections is not None and violations == []
    assert calls[0] is None and any("203.0.113.9" in v for v in calls[1])


def test_writer_that_keeps_inventing_is_rejected(aws_facts):
    sections, violations = writers.write_validated(lambda f, fb=None: _sections("From 203.0.113.9."), aws_facts)
    assert sections is None and violations


def test_upgrade_falls_through_to_next_writer(monkeypatch, aws_facts):
    good = lambda f, fb=None: _sections("A Critical leak, 22 minutes.")  # noqa: E731
    bad = lambda f, fb=None: None  # noqa: E731
    monkeypatch.setattr(writers, "_writers", lambda: [("local_model", bad), ("gemini", good)])
    text, source = writers.upgrade_report(aws_facts)
    assert source == "gemini" and "A Critical leak" in text


def test_no_writers_means_no_upgrade(monkeypatch, aws_facts):
    monkeypatch.setattr(writers, "_writers", lambda: [])
    assert writers.upgrade_report(aws_facts) is None


# ==========================================================================
# Pipeline integration
# ==========================================================================

def _run_pipeline(sqlite_factory, monkeypatch, upgrade):
    events = [_ev("stripe", "charge.succeeded", "api.stripe.com", "ch_1",
                  raw={"data": {"object": {"id": "ch_1", "object": "charge", "amount": 1000, "currency": "usd"}}})]

    class Collector:
        def collect(self, credential, start_time, end_time):
            return [e.model_copy() for e in events]

    monkeypatch.setattr(pipeline, "SessionLocal", sqlite_factory)
    monkeypatch.setitem(pipeline._COLLECTOR_MAP, "stripe", Collector)
    monkeypatch.setattr(pipeline, "upgrade_report", upgrade)

    from db.crud import create_incident
    incident = create_incident(
        sqlite_factory(), credential_type="stripe_secret_key", credential_hint="sk_live_****abcd",
        repo_url="https://github.com/demo/leaky", commit_hash="abc", exposure_start=T0,
        principal_id="sk_live_****abcd",
    )
    pipeline.run_collection_pipeline(incident.incident_id, "sk_live_x", T0, platform="stripe")
    return sqlite_factory().get(IncidentRecord, incident.incident_id)


def test_pipeline_upgrades_report_when_model_output_validates(sqlite_factory, monkeypatch):
    stored = _run_pipeline(
        sqlite_factory, monkeypatch,
        lambda facts: (render_report(facts, _sections("Model-written summary.")), "local_model"),
    )
    assert stored.status == "complete"
    assert stored.report_source == "local_model"
    assert "Model-written summary." in stored.report_text
    assert stored.remediation_steps and stored.remediation_steps[0].startswith("☐ Revoke")


def test_pipeline_keeps_template_when_upgrade_fails(sqlite_factory, monkeypatch):
    def boom(facts):
        raise RuntimeError("model crashed")

    stored = _run_pipeline(sqlite_factory, monkeypatch, boom)
    assert stored.status == "complete"            # never 'error' because of the writer
    assert stored.report_source == "deterministic"
    assert "Stripe" in stored.report_text


def test_pipeline_indexes_the_incident_for_search(sqlite_factory, monkeypatch):
    from db.models import KnowledgeChunk

    stored = _run_pipeline(sqlite_factory, monkeypatch, lambda facts: None)
    chunks = sqlite_factory().query(KnowledgeChunk).filter(KnowledgeChunk.source_id == stored.incident_id).all()
    assert chunks and any("Executive Summary" in c.title for c in chunks)
    assert all("sk_live_x" not in c.text for c in chunks)


# ==========================================================================
# Regressions from a real run of an untuned 0.5B model
# ==========================================================================

@pytest.fixture
def one_charge_facts():
    return _facts("stripe", [_ev(
        "stripe", "charge.succeeded", "api.stripe.com", "ch_9",
        raw={"data": {"object": {"id": "ch_9", "object": "charge", "amount": 41250, "currency": "usd"}}},
    )])


def test_validator_rejects_activity_that_did_not_happen(one_charge_facts):
    """Observed: one charge summarised as 'charges, refunds, and payouts'."""
    violations = validate_sections(
        _sections("A critical event resulted in charges, refunds, and payouts."), one_charge_facts
    )
    assert any("refunds" in v for v in violations) and any("payouts" in v for v in violations)


def test_validator_allows_generic_blind_spot_wording(one_charge_facts):
    text = "Stripe Events record state changes only, such as charges, refunds and payouts."
    assert validate_sections(_sections(text), one_charge_facts) == []


def test_validator_rejects_raw_field_names(one_charge_facts):
    """Observed: 'Event_count: 3' and 'Categories: privilege_escalation' in prose."""
    violations = validate_sections(_sections("Summary.", ["Event_count: 1", "privilege_escalation"]), one_charge_facts)
    assert any("event_count" in v for v in violations)
    assert any("privilege_escalation" in v for v in violations)


def test_local_model_requires_a_passing_gate(tmp_path, monkeypatch):
    """An unevaluated model must never reach users, even if it is installed."""
    import config
    from reporter import local_model

    model = tmp_path / "reporter.gguf"
    model.write_bytes(b"not really a model")
    monkeypatch.setattr(config, "REPORT_MODEL_REQUIRE_GATE", True)
    monkeypatch.setattr(local_model.LocalReportModel, "runtime_installed", staticmethod(lambda: True))
    candidate = local_model.LocalReportModel(str(model))

    assert not candidate.available()                     # no manifest

    manifest = tmp_path / "reporter.gguf.gate.json"
    sha = local_model._file_sha256(str(model))
    manifest.write_text(json.dumps({"passed": False, "model_sha256": sha}))
    assert not candidate.available()                     # failed gate

    manifest.write_text(json.dumps({"passed": True, "model_sha256": "0" * 64}))
    assert not candidate.available()                     # gate was for a different file

    manifest.write_text(json.dumps({"passed": True, "model_sha256": sha}))
    assert candidate.available()
