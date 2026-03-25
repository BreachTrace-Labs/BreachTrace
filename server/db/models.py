"""
SQLAlchemy ORM models — mirrors the DB schema from Section 5.2 of the spec.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class IncidentRecordDB(Base):
    __tablename__ = "incident_records"

    incident_id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    credential_type = Column(String(50), nullable=False)
    credential_hint = Column(String(20), nullable=False)
    access_key_id = Column(String(30))
    repo_url = Column(Text, nullable=False)
    commit_hash = Column(String(40))
    exposure_start = Column(DateTime(timezone=True), nullable=False)
    exposure_end = Column(DateTime(timezone=True))
    status = Column(String(20), default="detecting")
    overall_severity = Column(String(10))
    report_text = Column(Text)
    remediation_steps = Column(JSONB, default=list)
    gdpr_flag = Column(Boolean, default=False)
    financial_impact = Column(Text)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    events = relationship(
        "ForensicEventDB", back_populates="incident", cascade="all, delete-orphan"
    )
    collection_statuses = relationship(
        "CollectionStatusDB", back_populates="incident", cascade="all, delete-orphan"
    )
    experiment_runs = relationship(
        "ExperimentRunDB", back_populates="incident", cascade="all, delete-orphan"
    )


class ForensicEventDB(Base):
    __tablename__ = "forensic_events"

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incident_records.incident_id", ondelete="CASCADE"),
        nullable=False,
    )
    platform = Column(String(20), default="aws")
    timestamp = Column(DateTime(timezone=True), nullable=False)
    api_action = Column(String(100), nullable=False)
    event_source = Column(String(100))
    source_ip = Column(String(50))
    user_agent = Column(Text)
    affected_resource = Column(Text)
    resource_type = Column(String(100))
    success = Column(Boolean, default=True)
    error_code = Column(String(50))
    impact_category = Column(String(50))
    severity_weight = Column(
        Integer, CheckConstraint("severity_weight BETWEEN 1 AND 4")
    )
    raw_data = Column(JSONB, nullable=False)

    incident = relationship("IncidentRecordDB", back_populates="events")


class CollectionStatusDB(Base):
    __tablename__ = "collection_status"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incident_records.incident_id"),
    )
    platform = Column(String(20), default="aws")
    status = Column(String(20))  # success | no_activity | error
    event_count = Column(Integer, default=0)
    error_message = Column(Text)
    queried_at = Column(DateTime(timezone=True), default=_utcnow)

    incident = relationship("IncidentRecordDB", back_populates="collection_statuses")


class ExperimentRunDB(Base):
    __tablename__ = "experiment_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incident_records.incident_id"),
    )
    run_number = Column(Integer)
    experiment_group = Column(String(10))
    exposure_start = Column(DateTime(timezone=True))
    attacker_sim_start = Column(DateTime(timezone=True))
    detection_time_s = Column(Integer)
    report_time_s = Column(Integer)
    api_calls_made = Column(JSONB)
    impact_categories = Column(JSONB)
    overall_severity = Column(String(10))
    external_use_detected = Column(Boolean, default=False)
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    incident = relationship("IncidentRecordDB", back_populates="experiment_runs")
