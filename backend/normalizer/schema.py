from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ForensicEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    platform: str = "aws"
    timestamp: datetime
    api_action: str
    event_source: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    affected_resource: Optional[str] = None
    resource_type: Optional[str] = None
    success: bool = True
    error_code: Optional[str] = None
    raw_data: dict = Field(default_factory=dict)
    # Filled by classifier
    impact_category: Optional[str] = None
    severity_weight: Optional[int] = None  # 1=Low 2=Medium 3=High 4=Critical


class IncidentRecord(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_type: str = "aws_access_key"
    credential_hint: str                         # e.g. 'AKIA****WXYZ'
    access_key_id: str                           # Full AKIA... key ID (NOT the secret)
    repo_url: str
    commit_hash: str
    exposure_start: datetime
    exposure_end: Optional[datetime] = None
    status: str = "detecting"                    # detecting|collecting|classifying|scoring|reporting|complete
    events: list[ForensicEvent] = Field(default_factory=list)
    overall_severity: Optional[str] = None
    report_text: Optional[str] = None
    remediation_steps: list[str] = Field(default_factory=list)
    gdpr_flag: bool = False
    estimated_financial_impact: Optional[str] = None
