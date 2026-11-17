"""
GET  /research/export     — all experiment runs, for the Research page table
GET  /research/platforms  — per-platform comparison, for the headline chart
POST /research/record     — persist one completed experiment run
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AliasChoices, BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from db.crud import get_incident
from db.database import get_db
from db.models import VALID_PLATFORMS, ExperimentRun
from redaction import mask_identifier
from research.analysis import compare_platforms, latency_by_platform

router = APIRouter(prefix="/research", tags=["research"])


class ExperimentRunOut(BaseModel):
    run_id: str = Field(validation_alias="id")
    access_key_id: Optional[str]
    # Float, not int: the harness measures to one decimal and truncating
    # 1.4s -> 1s is a ~30% error on the fastest platform.
    detection_time_s: Optional[float]
    report_time_s: Optional[float]
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
    first_external_use_s: Optional[float] = None
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
                    access_key_id=mask_identifier(incident.access_key_id) if incident else None,
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


# ---------------------------------------------------------------------------
# POST /research/record — the write path
#
# Until this existed, nothing in the codebase ever constructed an ExperimentRun.
# The table was never written to, so /export and /platforms always returned
# empty against a live backend and the Research page had no data source at all.
# ---------------------------------------------------------------------------

class ExperimentRunIn(BaseModel):
    """
    One completed experiment run, as posted by research/harness.py.

    Accepts both field spellings the codebase already tolerates: the harness
    emits `first_use_time_s` / `api_calls`, the DB uses `first_external_use_s` /
    `api_calls_made`. analysis.py already reads either, so rejecting one here
    would make the recorder stricter than the analysis it feeds.
    """

    incident_id: Optional[str] = None
    run_number: Optional[int] = None
    experiment_group: Optional[str] = None       # 'A' | 'B' | 'C'
    platform: str = "aws"
    exposure_start: Optional[datetime] = None
    attacker_sim_start: Optional[datetime] = None
    detection_time_s: Optional[float] = None
    report_time_s: Optional[float] = None
    first_external_use_s: Optional[float] = Field(
        None,
        validation_alias=AliasChoices("first_external_use_s", "first_use_time_s"),
    )
    api_calls_made: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("api_calls_made", "api_calls"),
    )
    impact_categories: list[str] = Field(default_factory=list)
    overall_severity: Optional[str] = None
    external_use_detected: bool = False
    notes: Optional[str] = None

    class Config:
        populate_by_name = True

    @field_validator("platform", mode="before")
    @classmethod
    def _normalise_platform(cls, value: object) -> str:
        """
        experiment_runs.platform has no CHECK constraint — the migration added
        one only to forensic_events and collection_status. A typo would create a
        phantom platform bar in the paper's headline figure, so validate here.
        """
        platform = str(value or "aws").strip().lower()
        if platform not in VALID_PLATFORMS:
            raise ValueError(
                f"Unknown platform {platform!r}. Expected one of: {', '.join(VALID_PLATFORMS)}"
            )
        return platform

    @field_validator("overall_severity", mode="before")
    @classmethod
    def _normalise_severity(cls, value: object) -> Optional[str]:
        """compare_platforms() and /incidents/stats both uppercase; match them
        so one campaign cannot produce both 'High' and 'HIGH' buckets."""
        if value is None:
            return None
        return str(value).strip().upper() or None


def _next_run_number(existing: list[int]) -> int:
    """Next sequential run number. Pure, so it is testable without a session."""
    numbers = [n for n in existing if isinstance(n, int)]
    return (max(numbers) + 1) if numbers else 1


@router.post("/record", response_model=ExperimentRunOut, status_code=201)
def record_experiment_run(body: ExperimentRunIn, db: Session = Depends(get_db)):
    """
    Persist one completed experiment run.

    Unlike /export and /platforms this deliberately does **not** swallow
    exceptions. A read that fails soft degrades a chart; a write that fails soft
    is how a 150-run campaign finishes with an empty table and nobody notices
    until analysis time.
    """
    incident = None
    if body.incident_id:
        incident = get_incident(db, body.incident_id)
        if incident is None:
            # Refusing the orphan rather than storing it: /export derives
            # event_count from the linked incident, so a null link would
            # contribute a real-looking 0 to the paper's events_collected stats.
            raise HTTPException(
                status_code=404,
                detail=f"Incident {body.incident_id!r} not found — refusing to record an orphan run",
            )

    # Upsert on incident_id. Sprint 4 calls for resume-after-failure across a
    # 150-run loop; without this a retried run double-counts total_runs.
    run: ExperimentRun | None = None
    if body.incident_id:
        run = (
            db.query(ExperimentRun)
            .filter(ExperimentRun.incident_id == body.incident_id)
            .first()
        )

    if run is None:
        run = ExperimentRun(id=str(uuid.uuid4()))
        db.add(run)

    run.incident_id = body.incident_id
    if body.run_number is not None:
        run.run_number = body.run_number
    elif run.run_number is None:
        run.run_number = _next_run_number(
            [row[0] for row in db.query(ExperimentRun.run_number).all()]
        )
    run.experiment_group = body.experiment_group
    run.platform = body.platform
    run.exposure_start = body.exposure_start
    run.attacker_sim_start = body.attacker_sim_start
    run.detection_time_s = body.detection_time_s
    run.report_time_s = body.report_time_s
    run.first_external_use_s = body.first_external_use_s
    run.api_calls_made = body.api_calls_made
    run.impact_categories = body.impact_categories
    run.overall_severity = body.overall_severity
    run.external_use_detected = body.external_use_detected
    run.notes = body.notes

    db.commit()
    db.refresh(run)

    return ExperimentRunOut(
        run_id=run.id,
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
