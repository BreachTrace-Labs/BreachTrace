"""
ForensicEvent + IncidentRecord Pydantic schemas.
These are the shared data contracts between all pipeline modules.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from uuid import uuid4


class ForensicEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str = ""
    platform: str = "aws"
    timestamp: datetime
    api_action: str
    event_source: str = ""
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    affected_resource: Optional[str] = None
    resource_type: Optional[str] = None
    success: bool = True
    error_code: Optional[str] = None
    raw_data: dict = {}

    # Filled by classifier
    impact_category: Optional[str] = None
    severity_weight: Optional[int] = None


class IncidentRecord(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    credential_type: str = "aws_access_key"
    credential_hint: str = ""
    access_key_id: str = ""
    repo_url: str = ""
    commit_hash: str = ""
    exposure_start: datetime = Field(default_factory=datetime.utcnow)
    exposure_end: Optional[datetime] = None
    status: str = "detecting"
    overall_severity: Optional[str] = None
    report_text: Optional[str] = None
    remediation_steps: list[str] = []
    gdpr_flag: bool = False
    financial_impact: Optional[str] = None
    events: list[ForensicEvent] = []


class CredentialMatch(BaseModel):
    """Returned by the credential scanner when a secret is found in a diff."""
    credential_type: str  # e.g. "aws_access_key"
    access_key_id: str    # full AKIA... key ID
    secret_key: Optional[str] = None  # adjacent secret if found
    hint: str             # masked: "AKIA****MPLE"
    line_number: int = 0


class ExperimentRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str = ""
    run_number: int = 0
    experiment_group: str = "A"
    exposure_start: Optional[datetime] = None
    attacker_sim_start: Optional[datetime] = None
    detection_time_s: int = 0
    report_time_s: int = 0
    api_calls_made: list[str] = []
    impact_categories: list[str] = []
    overall_severity: str = "Low"
    external_use_detected: bool = False
    notes: Optional[str] = None
