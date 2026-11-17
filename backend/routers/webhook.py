"""
POST /webhook/github   — receive GitHub push webhooks
POST /webhook/register — auto-register a webhook on a GitHub repo via the API
GET  /webhook/info     — return the configured webhook URL (for the Connect UI)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from github import Github, GithubException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import config
from auth import require_admin_or_lead
from db.crud import create_incident, finalize_non_forensic_incident, set_exposure_end
from db.database import SessionLocal, get_db
from detector.match_resolver import resolve_match
from detector.scanner import scan
from pipeline import run_collection_pipeline
from rag.index import index_incident_in_background
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
    credential: str,
    secret: str,
    db_factory,
    *,
    platform: str = "aws",
) -> None:
    """
    Poll the credential revocation endpoint every 60 s for up to 10 minutes.
    Sets exposure_end on the incident the moment the credential is revoked.
    """
    max_polls = 10  # 10 × 60 s = 10 minutes
    for _ in range(max_polls):
        await asyncio.sleep(60)
        try:
            revoked = is_key_revoked(credential, secret, platform=platform)
        except Exception as exc:
            logger.error("Revocation check failed for %s: %s", credential[:20], exc)
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
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Receive a GitHub push webhook, detect leaked AWS credentials, and persist incidents.
    """
    body = await request.body()
    
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    logger.info(f"======> [WEBHOOK HIT] Received '{event_type}' event <======")

    # 1. Validate HMAC-SHA256 signature
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(body, sig_header):
        logger.error(f"[WEBHOOK FAIL] Signature mismatch. Received: {sig_header[:25]}...")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Only process push events
    if event_type != "push":
        logger.info(f"[WEBHOOK] Ignored non-push event: {event_type}")
        return {"status": "ignored", "event": event_type}

    payload: dict = json.loads(body)

    repo_full_name: str = payload.get("repository", {}).get("full_name", "")
    repo_url: str = payload.get("repository", {}).get("html_url", "")
    commits: list[dict] = payload.get("commits", [])

    if not commits:
        logger.info(f"[WEBHOOK] No commits in push payload for repo {repo_full_name}")
        return {"status": "ignored", "reason": "no commits in payload"}

    created_incidents: list[str] = []
    logger.info(f"[WEBHOOK] Processing {len(commits)} commit(s) on {repo_full_name}...")

    # 3. Process each commit
    for commit in commits:
        sha: str = commit.get("id", "")
        timestamp_str: str = commit.get("timestamp", "")

        if not sha or not timestamp_str:
            continue

        exposure_start: datetime = record_exposure_start(timestamp_str)

        # 4. Fetch the commit diff
        logger.info(f"[WEBHOOK PROCESS] Fetching diff for {sha}...")
        diff_text = _fetch_diff(repo_full_name, sha)
        if not diff_text:
            logger.info(f"[WEBHOOK FAIL] Could not fetch diff text for {sha}.")
            continue

        # 5. Scan for AWS credentials
        logger.info(f"[WEBHOOK PROCESS] Scanning commit {sha}...")
        matches = scan(diff_text, include_saas=True)
        if not matches:
            logger.info(f"[WEBHOOK RESULT] No AWS secrets detected in commit {sha}.")
            continue

        logger.info(f"[WEBHOOK FOUND] Found {len(matches)} secret(s) in {sha}!")

        for match in matches:
            # 6. Normalise the match — see detector/match_resolver.py
            resolved = resolve_match(match)
            match_platform = resolved.platform
            credential = resolved.credential

            incident = create_incident(
                db,
                credential_type=resolved.credential_type,
                credential_hint=resolved.credential_hint,
                access_key_id=resolved.access_key_id,
                repo_url=repo_url,
                commit_hash=sha,
                exposure_start=exposure_start,
                principal_id=resolved.principal_id,
                forensic_tier=resolved.forensic_tier,
                unavailable_reason=resolved.unavailable_reason,
            )
            created_incidents.append(incident.incident_id)
            logger.info(
                "Incident created: %s | platform: %s | tier: %s | hint: %s | repo: %s",
                incident.incident_id,
                match_platform,
                resolved.forensic_tier,
                resolved.credential_hint,
                repo_url,
            )

            if resolved.is_collectable:
                background_tasks.add_task(
                    run_collection_pipeline,
                    incident.incident_id,
                    credential,
                    exposure_start,
                    platform=match_platform,
                )
            else:
                # Tier 2: nothing to query. Finalise now with the reason recorded
                # rather than leaving the incident stuck in 'collecting' forever.
                finalize_non_forensic_incident(
                    db, incident.incident_id, resolved.unavailable_reason
                )
                background_tasks.add_task(index_incident_in_background, incident.incident_id)

            # Launch revocation monitor for known experiment credentials only.
            if match_platform == "aws" and credential == config.EXPERIMENT_AWS_ACCESS_KEY_ID:
                asyncio.create_task(
                    _monitor_revocation(
                        incident.incident_id,
                        credential,
                        config.EXPERIMENT_AWS_SECRET_ACCESS_KEY,
                        SessionLocal,
                        platform="aws",
                    )
                )
            elif match_platform == "gcp" and credential == config.GCP_EXPERIMENT_CLIENT_EMAIL:
                asyncio.create_task(
                    _monitor_revocation(
                        incident.incident_id,
                        credential,
                        getattr(match, "private_key_id", "") or "",
                        SessionLocal,
                        platform="gcp",
                    )
                )
            elif match_platform == "azure" and credential == config.AZURE_EXPERIMENT_CLIENT_ID:
                asyncio.create_task(
                    _monitor_revocation(
                        incident.incident_id,
                        credential,
                        config.AZURE_EXPERIMENT_CLIENT_SECRET,
                        SessionLocal,
                        platform="azure",
                    )
                )

    return {
        "status": "processed",
        "incidents_created": len(created_incidents),
        "incident_ids": created_incidents,
    }


# ---------------------------------------------------------------------------
# Webhook registration helpers
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    repo_url: str      # e.g. "https://github.com/user/repo"
    webhook_url: str   # e.g. "http://localhost:8000/webhook/github" or ngrok URL


@router.post("/register", status_code=200, dependencies=[Depends(require_admin_or_lead)])
async def register_webhook(body: RegisterRequest):
    """
    Use the configured GITHUB_TOKEN to register (or confirm) a push webhook on
    the target repo.  The frontend calls this when the user clicks
    'Connect Repository'.
    """
    # Parse "user/repo" from any GitHub URL form
    url = body.repo_url.rstrip("/")
    if "github.com/" not in url:
        raise HTTPException(status_code=400, detail="repo_url must be a GitHub repository URL")

    repo_full_name = url.split("github.com/", 1)[1]

    try:
        gh = Github(config.GITHUB_TOKEN)
        repo = gh.get_repo(repo_full_name)
    except GithubException as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot access repository '{repo_full_name}': {exc.data.get('message', str(exc))}",
        )

    # Check if our webhook URL is already registered
    try:
        existing_hooks = list(repo.get_hooks())
    except GithubException:
        existing_hooks = []

    for hook in existing_hooks:
        if hook.config.get("url", "") == body.webhook_url:
            return {
                "success": True,
                "already_existed": True,
                "webhook_id": hook.id,
                "message": f"Webhook already registered on {repo_full_name}",
            }

    # Register a new webhook
    try:
        hook = repo.create_hook(
            name="web",
            config={
                "url": body.webhook_url,
                "content_type": "json",
                "secret": config.GITHUB_WEBHOOK_SECRET,
                "insecure_ssl": "0",
            },
            events=["push"],
            active=True,
        )
    except GithubException as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to create webhook: {exc.data.get('message', str(exc))}",
        )

    logger.info("Webhook registered on %s — hook id %s", repo_full_name, hook.id)
    return {
        "success": True,
        "already_existed": False,
        "webhook_id": hook.id,
        "message": f"Webhook registered on {repo_full_name}",
    }


@router.get("/info", dependencies=[Depends(require_admin_or_lead)])
async def webhook_info(request: Request):
    """
    Return the webhook URL the frontend should display and offer to register.
    Derives it from the incoming request's base URL so it works for both
    localhost and any deployed environment.
    """
    base = str(request.base_url).rstrip("/")
    return {
        "webhook_url": f"{base}/webhook/github",
        "secret_hint": config.GITHUB_WEBHOOK_SECRET[:4] + "****" if config.GITHUB_WEBHOOK_SECRET else "",
        "environment": config.ENVIRONMENT,
    }
