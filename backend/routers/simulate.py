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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.crud import create_incident, set_exposure_end
from db.database import SessionLocal, get_db
from detector.patterns import AzureCredentialMatch, GCPCredentialMatch
from detector.scanner import scan
from pipeline import run_collection_pipeline
from window.calculator import is_key_revoked

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/test", tags=["test"])


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class SimulateRequest(BaseModel):
    repo_url: str = "simulated"
    diff_text: str
    # Platform selector: 'aws' | 'gcp' | 'azure'
    platform: str = "aws"
    # Optional: force a specific credential so a match can be filtered.
    # AWS:   access_key_id (AKIA…)
    # GCP:   client_email (service account email)
    # Azure: client_id (UUID)
    credential: Optional[str] = None
    # AWS-specific: legacy field kept for backward compatibility.
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
    credential: str,
    secret: str,
    *,
    platform: str = "aws",
) -> None:
    """Poll revocation endpoint every 60 s for up to 10 minutes; set exposure_end when revoked."""
    max_polls = 10
    for poll in range(max_polls):
        await asyncio.sleep(60)
        try:
            revoked = is_key_revoked(credential, secret, platform=platform)
        except Exception as exc:
            logger.error(
                "Revocation poll %d failed for %s: %s", poll + 1, credential[:20], exc
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
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Feed a raw diff directly into the scanner and persist incidents to DB.
    Optionally starts revocation monitoring when both key parts are provided.
    """
    matches = scan(body.diff_text)

    if not matches:
        return {"status": "no_credentials_found", "incidents_created": 0}

    # Resolve the effective credential override (support both legacy access_key_id
    # and the new unified credential field).
    forced_credential: str | None = body.credential or body.access_key_id

    if forced_credential:
        # Filter to the specific match for this credential across all platforms.
        def _match_credential(m) -> bool:  # type: ignore[return]
            if isinstance(m, GCPCredentialMatch):
                return m.client_email == forced_credential
            if isinstance(m, AzureCredentialMatch):
                return (m.client_id or "") == forced_credential
            # AWS CredentialMatch
            return getattr(m, "access_key_id", None) == forced_credential

        matches = [m for m in matches if _match_credential(m)]
        if not matches:
            raise HTTPException(
                status_code=422,
                detail=f"Credential '{forced_credential}' not found in the provided diff_text",
            )

    exposure_start = body.exposure_start or datetime.now(tz=timezone.utc)
    created: list[dict] = []

    for match in matches:
        # Determine platform and credential identifier from match type.
        if isinstance(match, GCPCredentialMatch):
            match_platform = "gcp"
            credential = match.client_email
            incident_access_key_id = None
            incident_principal_id = match.client_email
        elif isinstance(match, AzureCredentialMatch):
            match_platform = "azure"
            credential = match.client_id or ""
            incident_access_key_id = None
            incident_principal_id = match.client_id
        else:
            # AWS CredentialMatch
            match_platform = "aws"
            credential = match.access_key_id
            incident_access_key_id = match.access_key_id
            incident_principal_id = None

        incident = create_incident(
            db,
            credential_type=match.credential_type,
            credential_hint=match.credential_hint,
            access_key_id=incident_access_key_id,
            repo_url=body.repo_url,
            commit_hash="simulated",
            exposure_start=exposure_start,
            principal_id=incident_principal_id,
        )
        logger.info(
            "Simulated incident created: %s (platform=%s)",
            incident.incident_id,
            match_platform,
        )

        # Fire event collection in the background.
        background_tasks.add_task(
            run_collection_pipeline,
            incident.incident_id,
            credential,
            exposure_start,
            platform=match_platform,
        )

        # Start revocation monitor if a secret was provided.
        if body.secret_access_key and match_platform == "aws":
            asyncio.create_task(
                _monitor_revocation(
                    incident.incident_id,
                    credential,
                    body.secret_access_key,
                    platform="aws",
                )
            )

        created.append(
            {
                "incident_id": incident.incident_id,
                "credential_hint": match.credential_hint,
                "platform": match_platform,
                "revocation_monitor": body.secret_access_key is not None and match_platform == "aws",
            }
        )

    response: dict = {
        "status": "ok",
        "incidents_created": len(created),
        "incidents": created,
    }
    # Convenience field: top-level incident_id for single-incident responses
    # (used by the research harness to poll for pipeline completion).
    if len(created) == 1:
        response["incident_id"] = created[0]["incident_id"]
    return response
