"""
GET /research/export
---------------------
Returns all experiment run records for the Research page.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import ExperimentRun

router = APIRouter(prefix="/research", tags=["research"])


class ExperimentRunOut(BaseModel):
    run_id: str = Field(validation_alias="id")
    access_key_id: Optional[str]
    detection_time_s: Optional[int]
    report_time_s: Optional[int]
    api_calls: list[str]
    expected_severity: Optional[str]
    actual_severity: Optional[str]
    status: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


@router.get("/export", response_model=list[ExperimentRunOut])
def export_experiment_runs(db: Session = Depends(get_db)):
    """Return all experiment runs, ordered by run number, for the Research page."""
    try:
        runs = db.query(ExperimentRun).order_by(ExperimentRun.run_number).all()
    except Exception:
        return []
    result: list[ExperimentRunOut] = []
    for run in runs:
        try:
            incident = run.incident
            result.append(
                ExperimentRunOut(
                    id=run.id,
                    access_key_id=incident.access_key_id if incident else None,
                    detection_time_s=run.detection_time_s,
                    report_time_s=run.report_time_s,
                    api_calls=run.api_calls_made or [],
                    expected_severity=None,
                    actual_severity=run.overall_severity,
                    status=incident.status if incident else None,
                    created_at=run.created_at,
                )
            )
        except Exception:
            continue
    return result
