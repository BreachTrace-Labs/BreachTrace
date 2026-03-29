"""
POST /test/simulate
-------------------
Bypasses GitHub webhooks entirely — accepts raw diff text and credential
details directly so the full pipeline can be tested without a live repo.

Accepts an optional secret_access_key so the revocation monitor can be
started (useful for experiment runs where you control both key parts).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.crud import create_incident, set_exposure_end
from db.database import SessionLocal, get_db
from detector.scanner import scan
from window.calculator import is_key_revoked

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/test", tags=["test"])


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class SimulateRequest(BaseModel):
    repo_url: str
    diff_text: str
    # Optional: force a specific key ID + secret so revocation polling starts.
    # If omitted the scanner extracts the key ID from the diff.
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    # Override exposure start; defaults to now() if not provided
    exposure_start: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Revocation monitor (same logic as webhook.py — imported or duplicated for
# clarity since this is a separate code path used only in experiments)
# ---------------------------------------------------------------------------

async def _monitor_revocation(
    incident_id: str,
    access_key_id: str,
    secret_access_key: str,
) -> None:
    """Poll STS every 60 s for up to 10 minutes; set exposure_end when revoked."""
    max_polls = 10
    for poll in range(max_polls):
        await asyncio.sleep(60)
        try:
            revoked = is_key_revoked(access_key_id, secret_access_key)
        except Exception as exc:
            logger.error(
                "STS revocation poll %d failed for %s: %s", poll + 1, access_key_id, exc
            )
            continue

        if revoked:
            db: Session = SessionLocal()
            try:
                set_exposure_end(db, incident_id, datetime.now(tz=timezone.utc))
                logger.info("Revocation detected — exposure_end set for incident %s", incident_id)
            finally:
                db.close()
            return

    logger.warning("Revocation monitor timed out for incident %s", incident_id)


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/simulate", status_code=202)
async def simulate(
    body: SimulateRequest,
    db: Session = Depends(get_db),
):
    """
    Feed a raw diff directly into the scanner and persist incidents to DB.
    Optionally starts revocation monitoring when both key parts are provided.
    """
    matches = scan(body.diff_text)

    if not matches:
        return {"status": "no_credentials_found", "incidents_created": 0}

    # If the caller forced a specific key ID, filter to just that match or
    # create a synthetic match if the diff doesn't contain it.
    if body.access_key_id:
        matches = [m for m in matches if m.access_key_id == body.access_key_id]
        if not matches:
            raise HTTPException(
                status_code=422,
                detail=f"access_key_id '{body.access_key_id}' not found in the provided diff_text",
            )

    exposure_start = body.exposure_start or datetime.now(tz=timezone.utc)
    created: list[dict] = []

    for match in matches:
        incident = create_incident(
            db,
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            access_key_id=match.access_key_id,
            repo_url=body.repo_url,
            commit_hash="simulated",
            exposure_start=exposure_start,
        )
        logger.info("Simulated incident created: %s", incident.incident_id)

        # Start revocation monitor if credentials provided
        if body.secret_access_key:
            asyncio.create_task(
                _monitor_revocation(
                    incident.incident_id,
                    match.access_key_id,
                    body.secret_access_key,
                )
            )

        created.append(
            {
                "incident_id": incident.incident_id,
                "credential_hint": match.credential_hint,
                "revocation_monitor": body.secret_access_key is not None,
            }
        )

    return {
        "status": "ok",
        "incidents_created": len(created),
        "incidents": created,
    }
