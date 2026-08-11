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
from research.analysis import compare_platforms, latency_by_platform

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
    # Without these the Research page's per-platform comparison — the paper's
    # headline result — has no data source. compare_platforms() groups on
    # `platform` and reads `first_external_use_s` / `event_count`.
    platform: str = "aws"
    run_number: Optional[int] = None
    experiment_group: Optional[str] = None
    first_external_use_s: Optional[int] = None
    external_use_detected: bool = False
    event_count: int = 0

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
                    platform=run.platform or "aws",
                    run_number=run.run_number,
                    experiment_group=run.experiment_group,
                    first_external_use_s=run.first_external_use_s,
                    external_use_detected=bool(run.external_use_detected),
                    event_count=len(incident.events) if incident else 0,
                )
            )
        except Exception:
            continue
    return result


@router.get("/platforms")
def compare_platforms_endpoint(db: Session = Depends(get_db)):
    """
    Per-platform experiment statistics — the paper's headline comparison and
    the Research page's grouped latency chart.

    Serves the analysis functions directly rather than making the frontend
    re-derive statistics from raw rows, so the chart and the paper table are
    guaranteed to quote the same numbers.
    """
    try:
        runs = db.query(ExperimentRun).all()
    except Exception:
        runs = []

    run_dicts = [
        {
            "platform": run.platform or "aws",
            "detection_time_s": run.detection_time_s,
            "report_time_s": run.report_time_s,
            "first_external_use_s": run.first_external_use_s,
            "overall_severity": run.overall_severity,
            "experiment_group": run.experiment_group,
            # `status` drives completion_rate; the incident is the source of truth.
            "status": run.incident.status if run.incident else None,
            "event_count": len(run.incident.events) if run.incident else 0,
        }
        for run in runs
    ]

    return {
        "total_runs": len(run_dicts),
        "by_platform": compare_platforms(run_dicts),
        # Platforms with no timing data are omitted rather than reported as 0.0
        # so an unprovisioned platform cannot read as an instantaneous one.
        "detection_latency_by_platform": latency_by_platform(run_dicts),
    }
