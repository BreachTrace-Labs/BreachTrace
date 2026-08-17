import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    VARCHAR,
)
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

# ---------------------------------------------------------------------------
# Forensic tiers (see plan.md §1)
#
# Tier 1 — the platform exposes an audit log we can query, so blast radius is
#          reconstructable.
# Tier 2 — detection only. No queryable per-credential audit log exists, so the
#          incident carries an exposure window, a credential class, remediation
#          steps, and an explicit reason reconstruction is impossible.
#
# Kept as plain ints rather than an Enum so the DB column stays trivially
# queryable and the JSON API stays boring.
# ---------------------------------------------------------------------------
TIER_FORENSIC = 1
TIER_DETECTION_ONLY = 2

# Every platform string that may appear on forensic_events / collection_status.
# Must stay in sync with the CHECK constraints below.
VALID_PLATFORMS = (
    "aws", "gcp", "azure", "firebase",          # cloud (Tier 1)
    "stripe", "twilio",                         # SaaS (Tier 1)
    "github", "slack", "npm", "sendgrid", "huggingface", "db",  # Tier 2
)

_PLATFORM_SQL_LIST = ", ".join(f"'{p}'" for p in VALID_PLATFORMS)

# credential_type -> platform. The detector owns credential_type; this is the
# single place that maps it onto a collector/taxonomy selector.
CREDENTIAL_TYPE_TO_PLATFORM: dict[str, str] = {
    "aws_access_key": "aws",
    "gcp_service_account": "gcp",
    # Firebase admin SDK keys ARE GCP service account keys and land in Cloud
    # Audit Logs, so they route to the GCP collector while keeping their own
    # label for the report.
    "firebase_service_account": "gcp",
    "azure_service_principal": "azure",
    "azure_client_secret": "azure",
    "azure_storage_connection": "azure",
    "stripe_secret_key": "stripe",
    "twilio_account_sid": "twilio",
    "github_pat": "github",
    "slack_webhook": "slack",
    "slack_token": "slack",
    "npm_token": "npm",
    "sendgrid_api_key": "sendgrid",
    "huggingface_token": "huggingface",
    "db_connection_string": "db",
}

# ---------------------------------------------------------------------------
# 1. incident_records
# ---------------------------------------------------------------------------
class IncidentRecord(Base):
    """
    One row per detected credential leak event.
    Central table that all other tables reference.
    """

    __tablename__ = "incident_records"

    incident_id = Column(
        String(36),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        comment="UUID primary key",
    )
    credential_type = Column(
        VARCHAR(50),
        nullable=False,
        comment="e.g. 'aws_access_key'",
    )
    credential_hint = Column(
        VARCHAR(50),
        nullable=False,
        comment="Masked key: 'AKIA****MPLE' — 50 chars covers all 7 credential types",
    )
    access_key_id = Column(
        VARCHAR(30),
        nullable=True,
        comment="Full AKIA... key ID (NOT the secret) — needed for CloudTrail query",
    )
    principal_arn = Column(
        VARCHAR(200),
        nullable=True,
        comment="IAM ARN from CloudTrail: arn:aws:iam::123456789:user/attacker",
    )
    repo_url = Column(Text, nullable=False, comment="GitHub repo where key was found")
    commit_hash = Column(VARCHAR(40), nullable=True, comment="40-char SHA")
    exposure_start = Column(
        DateTime(timezone=True),
        nullable=False,
        comment="Commit timestamp — when the key became public",
    )
    exposure_end = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the key was revoked. NULL = still open.",
    )
    status = Column(
        VARCHAR(20),
        nullable=False,
        default="detecting",
        comment="Pipeline stage: detecting | collecting | classifying | scoring | reporting | complete",
    )
    overall_severity = Column(
        Integer,
        nullable=True,
        comment="1=Low 2=Medium 3=High 4=Critical",
    )
    report_text = Column(Text, nullable=True, comment="Full Gemini-generated report")
    remediation_steps = Column(
        JSONB,
        nullable=False,
        default=list,
        comment="Parsed checklist items from Gemini output",
    )
    gdpr_flag = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if personal data access was detected",
    )
    financial_impact = Column(
        Text,
        nullable=True,
        comment="Formatted string: e.g. 'EC2: 2x t2.micro at $0.02/hr'",
    )

    # GCP / Azure multi-platform fields
    gcp_project_id = Column(
        VARCHAR(100),
        nullable=True,
        comment="GCP project where the leaked service account lives",
    )
    azure_tenant_id = Column(
        VARCHAR(50),
        nullable=True,
        comment="Azure Active Directory tenant ID",
    )
    azure_subscription_id = Column(
        VARCHAR(50),
        nullable=True,
        comment="Azure subscription ID",
    )
    principal_id = Column(
        VARCHAR(300),
        nullable=True,
        comment="Unified identity: GCP service account email or Azure client ID",
    )

    # ── Forensic tier ──────────────────────────────────────────────────────
    forensic_tier = Column(
        Integer,
        nullable=False,
        default=TIER_FORENSIC,
        server_default="1",
        comment="1 = audit log queryable (blast radius reconstructable); "
                "2 = detection only, no queryable audit log exists",
    )
    unavailable_reason = Column(
        Text,
        nullable=True,
        comment="Tier 2 only: why forensic reconstruction is impossible for this "
                "platform. Shown verbatim in the UI instead of an empty timeline.",
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    events = relationship(
        "ForensicEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="ForensicEvent.timestamp",
    )
    collection_statuses = relationship(
        "CollectionStatus",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    experiment_runs = relationship(
        "ExperimentRun",
        back_populates="incident",
        cascade="all, delete-orphan",
    )

    # Indexes
    __table_args__ = (
        Index("ix_incident_records_credential_type", "credential_type"),
        Index("ix_incident_records_exposure_start", "exposure_start"),
        Index("ix_incident_records_status", "status"),
    )

    @property
    def platform(self) -> str:
        """
        Derive the platform from credential_type (not a DB column).

        Uses an explicit map rather than substring matching. The old
        `"gcp" in ctype` form breaks as soon as credential types multiply — a
        `gcp_service_account` and a `db_connection_string` both contain
        substrings that collide with other platform names, and silently
        mis-routing an incident to the wrong collector is hard to notice.
        Unknown types fall back to 'aws', matching the schema default.
        """
        return CREDENTIAL_TYPE_TO_PLATFORM.get(
            (self.credential_type or "").lower(), "aws"
        )

    @property
    def is_forensic_tier(self) -> bool:
        """True when this platform has a queryable audit log (Tier 1)."""
        return (self.forensic_tier or TIER_FORENSIC) == TIER_FORENSIC

    def __repr__(self) -> str:
        return (
            f"<IncidentRecord id={self.incident_id!r} "
            f"hint={self.credential_hint!r} status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# 2. forensic_events
# ---------------------------------------------------------------------------
class ForensicEvent(Base):
    """
    One row per AWS CloudTrail event collected during an exposure window.
    Filled in two passes:
      Pass 1 (collector):   platform … raw_data
      Pass 2 (classifier):  impact_category, severity_weight
    """

    __tablename__ = "forensic_events"

    event_id = Column(
        String(36),
        primary_key=True,
        server_default=func.gen_random_uuid(),
        comment="UUID, auto-generated",
    )
    incident_id = Column(
        String(36),
        ForeignKey("incident_records.incident_id", ondelete="CASCADE"),
        nullable=False,
    )
    platform = Column(
        VARCHAR(20),
        nullable=False,
        default="aws",
        comment="Always 'aws' this week",
    )
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        comment="EventTime from CloudTrail (UTC)",
    )
    api_action = Column(
        VARCHAR(100),
        nullable=False,
        comment="EventName: e.g. 'GetObject', 'RunInstances'",
    )
    event_source = Column(
        VARCHAR(100),
        nullable=True,
        comment="EventSource: e.g. 's3.amazonaws.com'",
    )
    source_ip = Column(
        VARCHAR(50),
        nullable=True,
        comment="SourceIPAddress from CloudTrail",
    )
    user_agent = Column(Text, nullable=True, comment="UserAgent from CloudTrail")
    affected_resource = Column(
        Text,
        nullable=True,
        comment="Resources[0].ResourceName (first resource)",
    )
    principal_arn = Column(
        VARCHAR(200),
        nullable=True,
        comment="IAM ARN of the actor who made this API call",
    )
    resource_type = Column(
        VARCHAR(100),
        nullable=True,
        comment="Resources[0].ResourceType: 'AWS::S3::Bucket' etc.",
    )
    success = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="True if ErrorCode is absent",
    )
    error_code = Column(
        VARCHAR(50),
        nullable=True,
        comment="ErrorCode if present (AccessDenied etc.)",
    )
    is_denied = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True when ErrorCode is AccessDenied — high reconnaissance signal",
    )
    raw_data = Column(
        JSONB,
        nullable=False,
        comment="Full original CloudTrail event dict",
    )

    # GCP / Azure identity and location fields
    principal_id = Column(
        VARCHAR(300),
        nullable=True,
        comment="GCP service account email or Azure client ID (principalEmail / caller)",
    )
    location = Column(
        VARCHAR(200),
        nullable=True,
        comment="GCP region/zone or Azure resource group",
    )

    # Filled by classifier
    impact_category = Column(
        VARCHAR(50),
        nullable=True,
        comment="One of 8 categories: reconnaissance, data_access, exfiltration, "
                "resource_abuse, privilege_escalation, financial_abuse, communication_abuse, code_compromise",
    )
    severity_weight = Column(
        Integer,
        nullable=True,
        comment="1=Low 2=Medium 3=High 4=Critical",
    )

    # Relationship
    incident = relationship("IncidentRecord", back_populates="events")

    # Constraints + Indexes
    __table_args__ = (
        CheckConstraint(
            "severity_weight BETWEEN 1 AND 4",
            name="ck_forensic_events_severity_weight",
        ),
        CheckConstraint(
            f"platform IN ({_PLATFORM_SQL_LIST})",
            name="ck_forensic_events_platform_valid",
        ),
        Index("ix_forensic_events_incident_id", "incident_id"),
        Index("ix_forensic_events_timestamp", "timestamp"),
        Index("ix_forensic_events_impact_category", "impact_category"),
    )

    def __repr__(self) -> str:
        return (
            f"<ForensicEvent id={self.event_id!r} "
            f"action={self.api_action!r} category={self.impact_category!r}>"
        )


# ---------------------------------------------------------------------------
# 3. collection_status
# ---------------------------------------------------------------------------
class CollectionStatus(Base):
    """
    Tracks the result of each CloudTrail collection attempt.
    One row per (incident, platform) collection run.
    Allows retries to be recorded separately.
    """

    __tablename__ = "collection_status"

    id = Column(
        String(36),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    incident_id = Column(
        String(36),
        ForeignKey("incident_records.incident_id", ondelete="CASCADE"),
        nullable=False,
    )
    platform = Column(
        VARCHAR(20),
        nullable=False,
        default="aws",
        comment="Always 'aws' this week",
    )
    status = Column(
        VARCHAR(20),
        nullable=False,
        comment="success | no_activity | error",
    )
    event_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of ForensicEvents collected in this run",
    )
    error_message = Column(
        Text,
        nullable=True,
        comment="Populated when status='error'",
    )
    queried_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="When the CloudTrail lookup was made",
    )

    # Relationship
    incident = relationship("IncidentRecord", back_populates="collection_statuses")

    __table_args__ = (
        CheckConstraint(
            f"platform IN ({_PLATFORM_SQL_LIST})",
            name="ck_collection_status_platform_valid",
        ),
        CheckConstraint(
            "status IN ('success', 'no_activity', 'error')",
            name="ck_collection_status_status_valid",
        ),
        Index("ix_collection_status_incident_id", "incident_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<CollectionStatus incident={self.incident_id!r} "
            f"platform={self.platform!r} status={self.status!r} "
            f"events={self.event_count}>"
        )


# ---------------------------------------------------------------------------
# 4. experiment_runs
# ---------------------------------------------------------------------------
class ExperimentRun(Base):
    """
    Research harness results — Track B.
    One row per automated experiment run (35 total, 3 groups).

    Groups:
      A — standard reconnaissance (runs 1–12)
      B — bulk data access / exfiltration (runs 13–25)
      C — minimal activity (runs 26–35)
    """

    __tablename__ = "experiment_runs"

    id = Column(
        String(36),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    incident_id = Column(
        String(36),
        ForeignKey("incident_records.incident_id", ondelete="SET NULL"),
        nullable=True,
        comment="Linked incident produced by this run",
    )
    run_number = Column(Integer, nullable=True, comment="Sequential run counter (1–35)")
    experiment_group = Column(
        VARCHAR(10),
        nullable=True,
        comment="'A' (standard) | 'B' (bulk) | 'C' (minimal)",
    )
    platform = Column(
        VARCHAR(20),
        nullable=False,
        default="aws",
        server_default="aws",
        comment="Platform this run exercised. Without it the cross-platform "
                "comparison in research/analysis.py has nothing to group by, "
                "which is the paper's headline result.",
    )
    exposure_start = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the fake credential was committed",
    )
    attacker_sim_start = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When simulate_attacker_activity() was called",
    )
    detection_time_s = Column(
        Float,
        nullable=True,
        comment="Seconds from credential push to webhook detection",
    )
    first_external_use_s = Column(
        Float,
        nullable=True,
        comment="Seconds from exposure_start to first non-team IP usage — key research metric",
    )
    report_time_s = Column(
        Float,
        nullable=True,
        comment="Seconds from credential push to status=complete",
    )
    api_calls_made = Column(
        JSONB,
        nullable=True,
        comment="List of API action names the simulated attacker made",
    )
    impact_categories = Column(
        JSONB,
        nullable=True,
        comment="List of impact categories found in this run",
    )
    overall_severity = Column(
        VARCHAR(10),
        nullable=True,
        comment="Low | Medium | High | Critical",
    )
    external_use_detected = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if a non-team IP used the key during the window",
    )
    notes = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationship
    incident = relationship("IncidentRecord", back_populates="experiment_runs")

    __table_args__ = (
        Index("ix_experiment_runs_run_number", "run_number"),
        Index("ix_experiment_runs_experiment_group", "experiment_group"),
        # compare_platforms() groups by this on every research page load.
        Index("ix_experiment_runs_platform", "platform"),
    )

    def __repr__(self) -> str:
        return (
            f"<ExperimentRun #{self.run_number} "
            f"group={self.experiment_group!r} "
            f"severity={self.overall_severity!r}>"
        )
