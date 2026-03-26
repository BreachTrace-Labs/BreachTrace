import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from db.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    credential_type = Column(String, nullable=False)
    credential_hint = Column(String, nullable=False)
    access_key_id = Column(String, nullable=False)
    repo_url = Column(String, nullable=False)
    commit_hash = Column(String, nullable=False)
    exposure_start = Column(DateTime(timezone=True), nullable=False)
    exposure_end = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, default="detecting")
    overall_severity = Column(String, nullable=True)
    report_text = Column(Text, nullable=True)
    remediation_steps = Column(JSONB, nullable=True, default=list)
    gdpr_flag = Column(Boolean, nullable=False, default=False)
    estimated_financial_impact = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    events = relationship("ForensicEventModel", back_populates="incident", cascade="all, delete-orphan")


class ForensicEventModel(Base):
    __tablename__ = "forensic_events"

    event_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=False)
    platform = Column(String, nullable=False, default="aws")
    timestamp = Column(DateTime(timezone=True), nullable=False)
    api_action = Column(String, nullable=False)
    event_source = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    affected_resource = Column(String, nullable=True)
    resource_type = Column(String, nullable=True)
    success = Column(Boolean, nullable=False, default=True)
    error_code = Column(String, nullable=True)
    raw_data = Column(JSONB, nullable=False, default=dict)
    impact_category = Column(String, nullable=True)
    severity_weight = Column(Integer, nullable=True)

    incident = relationship("Incident", back_populates="events")


class ExperimentRun(Base):
    __tablename__ = "experiment_runs"

    run_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=True)
    credential_type = Column(String, nullable=False)
    exposure_start = Column(DateTime(timezone=True), nullable=True)
    first_use_at = Column(DateTime(timezone=True), nullable=True)
    time_to_first_use_seconds = Column(Integer, nullable=True)
    time_to_detection_seconds = Column(Integer, nullable=True)
    time_to_report_seconds = Column(Integer, nullable=True)
    classification_correct = Column(Boolean, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
