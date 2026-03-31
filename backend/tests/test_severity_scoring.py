"""
Unit tests for incident severity scoring and financial impact estimation.

Tests the scoring rules, financial impact heuristics, and GDPR/PII detection logic.
"""

from datetime import datetime, timezone

import pytest

from normalizer.schema import ForensicEvent
from scorer.severity import (
    score_incident,
    compute_financial_impact,
    check_gdpr_flag,
    _is_large_object,
    CRITICAL_CATEGORIES,
)


def _make_event(
    api_action: str,
    *,
    impact_category: str = "reconnaissance",
    severity_weight: int | None = 1,
    affected_resource: str | None = None,
    event_source: str = "s3.amazonaws.com",
) -> ForensicEvent:
    """Helper to create a ForensicEvent for testing."""
    return ForensicEvent(
        event_id="test-event",
        platform="aws",
        timestamp=datetime(2026, 3, 30, 12, 0, tzinfo=timezone.utc),
        api_action=api_action,
        event_source=event_source,
        source_ip="1.2.3.4",
        success=True,
        raw_data={"eventName": api_action},
        impact_category=impact_category,
        severity_weight=severity_weight,
        affected_resource=affected_resource,
    )


class TestScoreIncident:
    """Tests for score_incident() - severity escalation rules."""

    def test_empty_list_returns_low(self):
        """Empty event list returns 'Low' severity."""
        assert score_incident([]) == "Low"

    def test_privilege_escalation_is_critical(self):
        """privilege_escalation category always triggers 'Critical'."""
        event = _make_event("AssumeRole", impact_category="privilege_escalation")
        assert score_incident([event]) == "Critical"

    def test_exfiltration_is_critical(self):
        """exfiltration category always triggers 'Critical'."""
        event = _make_event("GetObject", impact_category="exfiltration")
        assert score_incident([event]) == "Critical"

    def test_code_compromise_is_critical(self):
        """code_compromise category always triggers 'Critical'."""
        event = _make_event("PutObject", impact_category="code_compromise")
        assert score_incident([event]) == "Critical"

    def test_financial_abuse_with_weight_3_is_critical(self):
        """financial_abuse + weight >= 3 triggers 'Critical'."""
        event = _make_event(
            "RunInstances",
            impact_category="financial_abuse",
            severity_weight=3,
        )
        assert score_incident([event]) == "Critical"

    def test_financial_abuse_with_weight_4_is_critical(self):
        """financial_abuse + weight 4 triggers 'Critical'."""
        event = _make_event(
            "RunInstances",
            impact_category="financial_abuse",
            severity_weight=4,
        )
        assert score_incident([event]) == "Critical"

    def test_financial_abuse_with_weight_2_is_high(self):
        """financial_abuse + weight < 3 triggers 'High'."""
        event = _make_event(
            "RunInstances",
            impact_category="financial_abuse",
            severity_weight=2,
        )
        assert score_incident([event]) == "High"

    def test_financial_abuse_with_weight_1_is_high(self):
        """financial_abuse + weight 1 still triggers 'High'."""
        event = _make_event(
            "RunInstances",
            impact_category="financial_abuse",
            severity_weight=1,
        )
        assert score_incident([event]) == "High"

    def test_weight_4_maps_to_critical(self):
        """Weight 4 maps to 'Critical' (no financial_abuse)."""
        event = _make_event("GetObject", severity_weight=4)
        assert score_incident([event]) == "Critical"

    def test_weight_3_maps_to_high(self):
        """Weight 3 maps to 'High' (no financial_abuse)."""
        event = _make_event("GetObject", severity_weight=3)
        assert score_incident([event]) == "High"

    def test_weight_2_maps_to_medium(self):
        """Weight 2 maps to 'Medium'."""
        event = _make_event("GetObject", severity_weight=2)
        assert score_incident([event]) == "Medium"

    def test_weight_1_maps_to_low(self):
        """Weight 1 maps to 'Low'."""
        event = _make_event("GetObject", severity_weight=1)
        assert score_incident([event]) == "Low"

    def test_weight_0_maps_to_low(self):
        """Weight 0 maps to 'Low'."""
        event = _make_event("GetObject", severity_weight=0)
        assert score_incident([event]) == "Low"

    def test_no_weight_defaults_to_low(self):
        """Event with no weight defaults to 'Low'."""
        event = _make_event("GetObject", severity_weight=None)
        assert score_incident([event]) == "Low"

    def test_multiple_events_max_weight_wins(self):
        """With multiple events, max weight determines severity."""
        events = [
            _make_event("GetObject", severity_weight=1),
            _make_event("ListBuckets", severity_weight=3),
            _make_event("PutObject", severity_weight=2),
        ]
        assert score_incident(events) == "High"

    def test_critical_categories_override_weight(self):
        """Critical categories override weight-based scoring."""
        events = [
            _make_event("GetObject", severity_weight=0),
            _make_event(
                "CreateAccessKey",
                impact_category="privilege_escalation",
                severity_weight=1,
            ),
        ]
        assert score_incident(events) == "Critical"

    def test_mixed_categories_critical_wins(self):
        """If any critical category present, result is 'Critical'."""
        events = [
            _make_event("GetObject", impact_category="data_access", severity_weight=1),
            _make_event(
                "GetBucket", impact_category="exfiltration", severity_weight=2
            ),
        ]
        assert score_incident(events) == "Critical"


class TestComputeFinancialImpact:
    """Tests for compute_financial_impact() - cost estimation."""

    def test_empty_list_returns_no_impact(self):
        """Empty event list returns 'No financial impact detected'."""
        assert compute_financial_impact([]) == "No financial impact detected"

    def test_recognizes_ec2_launches(self):
        """RunInstances events trigger EC2 cost estimate."""
        events = [_make_event("RunInstances", event_source="ec2.amazonaws.com")]
        result = compute_financial_impact(events)
        assert "EC2" in result
        assert "t2.micro" in result

    def test_counts_multiple_ec2_launches(self):
        """Multiple RunInstances events are counted."""
        events = [
            _make_event("RunInstances", event_source="ec2.amazonaws.com"),
            _make_event("RunInstances", event_source="ec2.amazonaws.com"),
            _make_event("RunInstances", event_source="ec2.amazonaws.com"),
        ]
        result = compute_financial_impact(events)
        assert "3x t2.micro" in result

    def test_large_object_transfer_costs(self):
        """GetObject with large resource name triggers data transfer cost."""
        events = [
            _make_event(
                "GetObject",
                affected_resource="s3://bucket/large-archive-2026-backup.tar.gz",
            )
        ]
        result = compute_financial_impact(events)
        assert "Data transfer" in result

    def test_ignores_small_object_transfer(self):
        """GetObject with normal resource name doesn't trigger cost."""
        events = [_make_event("GetObject", affected_resource="s3://bucket/config.json")]
        result = compute_financial_impact(events)
        assert "Data transfer" not in result

    def test_rds_instance_create_detected(self):
        """CreateDBInstance triggers RDS cost estimate."""
        events = [_make_event("CreateDBInstance", event_source="rds.amazonaws.com")]
        result = compute_financial_impact(events)
        assert "RDS" in result

    def test_rds_cluster_create_detected(self):
        """CreateDBCluster triggers RDS cost estimate."""
        events = [_make_event("CreateDBCluster", event_source="rds.amazonaws.com")]
        result = compute_financial_impact(events)
        assert "RDS" in result

    def test_eks_cluster_create_detected(self):
        """CreateCluster with eks.amazonaws.com source triggers EKS cost."""
        events = [
            _make_event(
                "CreateCluster",
                event_source="eks.amazonaws.com",
            )
        ]
        result = compute_financial_impact(events)
        assert "EKS" in result
        assert "cluster" in result.lower()

    def test_non_eks_create_cluster_ignored(self):
        """CreateCluster with non-EKS source is not counted as EKS."""
        events = [
            _make_event(
                "CreateCluster",
                event_source="redshift.amazonaws.com",
            )
        ]
        result = compute_financial_impact(events)
        assert "EKS" not in result

    def test_multiple_impact_types_combined(self):
        """Multiple impact types are combined in output."""
        events = [
            _make_event("RunInstances", event_source="ec2.amazonaws.com"),
            _make_event(
                "GetObject",
                affected_resource="backup-large-export.zip",
                event_source="s3.amazonaws.com",
            ),
            _make_event("CreateDBInstance", event_source="rds.amazonaws.com"),
        ]
        result = compute_financial_impact(events)
        assert "EC2" in result
        assert "Data transfer" in result
        assert "RDS" in result
        assert ". " in result  # Multiple impacts separated by period

    def test_no_recognized_patterns_returns_no_impact(self):
        """Events with no recognized patterns return 'No financial impact'."""
        events = [_make_event("ListBuckets"), _make_event("HeadObject")]
        result = compute_financial_impact(events)
        assert result == "No financial impact detected"


class TestCheckGdprFlag:
    """Tests for check_gdpr_flag() - PII/personal data detection."""

    def test_empty_list_returns_false(self):
        """Empty event list returns False."""
        assert check_gdpr_flag([]) is False

    def test_detects_user_in_data_access(self):
        """'user' in resource name + data_access triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/user-database.db",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_customer_in_exfiltration(self):
        """'customer' in resource + exfiltration triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="exfiltration",
            affected_resource="s3://bucket/customer-list.csv",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_email_keyword(self):
        """'email' in resource + data_access triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/emails-2026-q1.txt",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_pii_keyword(self):
        """'pii' in resource triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/pii-export.json",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_personal_keyword(self):
        """'personal' in resource triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="exfiltration",
            affected_resource="s3://bucket/personal-data.xlsx",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_ssn_keyword(self):
        """'ssn' in resource triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/employee-ssn-list.csv",
        )
        assert check_gdpr_flag([event]) is True

    def test_ignores_pii_hint_without_sensitive_category(self):
        """PII hint alone doesn't trigger flag without sensitive category."""
        event = _make_event(
            "GetObject",
            impact_category="reconnaissance",
            affected_resource="s3://bucket/user-config.json",
        )
        assert check_gdpr_flag([event]) is False

    def test_ignores_sensitive_category_without_pii_hint(self):
        """Sensitive category alone doesn't trigger flag without PII hint."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/public-docs.zip",
        )
        assert check_gdpr_flag([event]) is False

    def test_case_insensitive_matching(self):
        """PII hint matching is case-insensitive."""
        event = _make_event(
            "GetObject",
            impact_category="exfiltration",
            affected_resource="s3://bucket/USER-ACCOUNTS-2026.csv",
        )
        assert check_gdpr_flag([event]) is True

    def test_multiple_events_any_match_triggers(self):
        """Any event matching PII + sensitive category triggers flag."""
        events = [
            _make_event("ListBuckets", impact_category="reconnaissance"),
            _make_event(
                "GetObject",
                impact_category="data_access",
                affected_resource="s3://bucket/customer-data.db",
            ),
        ]
        assert check_gdpr_flag(events) is True

    def test_multiple_pii_hints_in_resource(self):
        """Resource with multiple PII hints still triggers flag once."""
        event = _make_event(
            "GetObject",
            impact_category="exfiltration",
            affected_resource="s3://bucket/user-customer-personal-data.json",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_private_keyword(self):
        """'private' in resource triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="data_access",
            affected_resource="s3://bucket/private-keys.pem",
        )
        assert check_gdpr_flag([event]) is True

    def test_detects_confidential_keyword(self):
        """'confidential' in resource triggers GDPR flag."""
        event = _make_event(
            "GetObject",
            impact_category="exfiltration",
            affected_resource="s3://bucket/confidential-docs.zip",
        )
        assert check_gdpr_flag([event]) is True


class TestIsLargeObject:
    """Tests for _is_large_object() - size heuristic."""

    def test_recognizes_large(self):
        """Resource name with 'large' is recognized."""
        assert _is_large_object("large-archive.tar.gz") is True

    def test_recognizes_big(self):
        """Resource name with 'big' is recognized."""
        assert _is_large_object("backup-big-export.sql") is True

    def test_recognizes_archive(self):
        """Resource name with 'archive' is recognized."""
        assert _is_large_object("s3://bucket/archive-2026.zip") is True

    def test_recognizes_backup(self):
        """Resource name with 'backup' is recognized."""
        assert _is_large_object("database-backup-full.tar") is True

    def test_recognizes_export(self):
        """Resource name with 'export' is recognized."""
        assert _is_large_object("data-export-q1-2026.csv") is True

    def test_recognizes_dump(self):
        """Resource name with 'dump' is recognized."""
        assert _is_large_object("mysql-dump-prod.sql") is True

    def test_ignores_small_files(self):
        """Small file names without size indicators are not recognized."""
        assert _is_large_object("config.json") is False
        assert _is_large_object("settings.yaml") is False
        assert _is_large_object("script.py") is False

    def test_case_insensitive_matching(self):
        """Size indicator matching is case-insensitive."""
        assert _is_large_object("BACKUP-2026.ZIP") is True
        assert _is_large_object("Export-Data.CSV") is True

    def test_partial_word_match(self):
        """Partial matches work (e.g., 'backup' in 'backup-2026')."""
        assert _is_large_object("backup-2026-full.tar.gz") is True
        assert _is_large_object("my-archive-full.tar") is True
