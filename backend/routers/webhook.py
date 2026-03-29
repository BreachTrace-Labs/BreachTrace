"""
POST /webhook/github
--------------------
Receives GitHub push-event webhooks, validates the HMAC-SHA256 signature,
extracts the commit diff, scans for AWS credentials, and creates an
IncidentRecord in the database for every match found.

A background coroutine is launched for each incident to monitor whether the
leaked key is revoked (polls AWS STS every 60 s for up to 10 minutes).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from github import Github, GithubException
from sqlalchemy.orm import Session

import config
from db.crud import create_incident, set_exposure_end
from db.database import SessionLocal, get_db
from detector.scanner import scan
from window.calculator import is_key_revoked, record_exposure_start

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhook", tags=["webhook"])


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------

def _verify_signature(body: bytes, sig_header: str) -> bool:
    """Return True if the X-Hub-Signature-256 header matches the HMAC of the body."""
    if not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        config.GITHUB_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig_header, expected)


# ---------------------------------------------------------------------------
# Diff fetching via PyGitHub
# ---------------------------------------------------------------------------

def _fetch_diff(repo_full_name: str, sha: str) -> str:
    """
    Fetch the unified diff for a commit using the GitHub API.
    Returns one big string with all file patches concatenated.
    """
    try:
        gh = Github(config.GITHUB_TOKEN)
        repo = gh.get_repo(repo_full_name)
        commit = repo.get_commit(sha)
        parts: list[str] = []
        for f in commit.files:
            if f.patch:
                parts.append(f.patch)
        return "\n".join(parts)
    except GithubException as exc:
        logger.warning("GitHub API error fetching diff %s@%s: %s", repo_full_name, sha, exc)
        return ""


# ---------------------------------------------------------------------------
# Revocation monitor (background coroutine)
# ---------------------------------------------------------------------------

async def _monitor_revocation(
    incident_id: str,
    access_key_id: str,
    secret_access_key: str,
    db_factory,
) -> None:
    """
    Poll AWS STS every 60 s for up to 10 minutes.
    Sets exposure_end on the incident the moment the key is revoked.
    """
    max_polls = 10  # 10 × 60 s = 10 minutes
    for _ in range(max_polls):
        await asyncio.sleep(60)
        try:
            revoked = is_key_revoked(access_key_id, secret_access_key)
        except Exception as exc:
            logger.error("STS revocation check failed for %s: %s", access_key_id, exc)
            continue

        if revoked:
            db: Session = db_factory()
            try:
                set_exposure_end(db, incident_id, datetime.now(tz=timezone.utc))
                logger.info("Exposure window closed for incident %s", incident_id)
            finally:
                db.close()
            return

    logger.warning(
        "Revocation monitor timed out after 10 minutes for incident %s", incident_id
    )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Receive a GitHub push webhook, detect leaked AWS credentials, and persist incidents.
    """
    body = await request.body()

    # 1. Validate HMAC-SHA256 signature
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(body, sig_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Only process push events
    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "push":
        return {"status": "ignored", "event": event_type}

    payload: dict = json.loads(body)

    repo_full_name: str = payload.get("repository", {}).get("full_name", "")
    repo_url: str = payload.get("repository", {}).get("html_url", "")
    commits: list[dict] = payload.get("commits", [])

    if not commits:
        return {"status": "ignored", "reason": "no commits in payload"}

    created_incidents: list[str] = []

    # 3. Process each commit
    for commit in commits:
        sha: str = commit.get("id", "")
        timestamp_str: str = commit.get("timestamp", "")

        if not sha or not timestamp_str:
            continue

        exposure_start: datetime = record_exposure_start(timestamp_str)

        # 4. Fetch the commit diff
        diff_text = _fetch_diff(repo_full_name, sha)
        if not diff_text:
            continue

        # 5. Scan for AWS credentials
        matches = scan(diff_text)
        if not matches:
            continue

        for match in matches:
            # 6. Persist incident
            incident = create_incident(
                db,
                credential_type=match.credential_type,
                credential_hint=match.credential_hint,
                access_key_id=match.access_key_id,
                repo_url=repo_url,
                commit_hash=sha,
                exposure_start=exposure_start,
            )
            created_incidents.append(incident.incident_id)
            logger.info(
                "Incident created: %s | key hint: %s | repo: %s",
                incident.incident_id,
                match.credential_hint,
                repo_url,
            )

            # Launch background revocation monitor
            asyncio.create_task(
                _monitor_revocation(
                    incident.incident_id,
                    match.access_key_id,
                    config.EXPERIMENT_AWS_SECRET_ACCESS_KEY,
                    SessionLocal,
                )
            )

    return {
        "status": "processed",
        "incidents_created": len(created_incidents),
        "incident_ids": created_incidents,
    }
