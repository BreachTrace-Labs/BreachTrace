import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
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
        """Derive cloud platform from credential_type (not a DB column)."""
        ctype = (self.credential_type or "").lower()
        if "gcp" in ctype:
            return "gcp"
        if "azure" in ctype:
            return "azure"
        return "aws"

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
            "platform IN ('aws', 'gcp', 'azure', 'stripe', 'github', 'twilio', 'db', 'npm')",
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
            "platform IN ('aws', 'gcp', 'azure', 'stripe', 'github', 'twilio', 'db', 'npm')",
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
        Integer,
        nullable=True,
        comment="Seconds from credential push to webhook detection",
    )
    first_external_use_s = Column(
        Integer,
        nullable=True,
        comment="Seconds from exposure_start to first non-team IP usage — key research metric",
    )
    report_time_s = Column(
        Integer,
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
    )

    def __repr__(self) -> str:
        return (
            f"<ExperimentRun #{self.run_number} "
            f"group={self.experiment_group!r} "
            f"severity={self.overall_severity!r}>"
        )
