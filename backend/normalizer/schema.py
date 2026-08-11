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
    # GCP / Azure identity and location (None for AWS events)
    principal_id: Optional[str] = None
    location: Optional[str] = None


class IncidentRecord(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_type: str = "aws_access_key"
    credential_hint: str                         # e.g. 'AKIA****WXYZ'
    # Only AWS has an access key ID. GCP/Azure/SaaS incidents identify the
    # credential via principal_id instead, so this cannot be required.
    access_key_id: Optional[str] = None
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
    # Multi-platform fields
    platform: str = "aws"
    gcp_project_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    principal_id: Optional[str] = None
    # Forensic tier: 1 = audit log queryable, 2 = detection only.
    # Tier 2 incidents carry unavailable_reason and never attempt collection.
    forensic_tier: int = 1
    unavailable_reason: Optional[str] = None
