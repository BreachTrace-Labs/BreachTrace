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
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from github import Github, GithubException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

import config
from access import assert_project_access
from auth import require_admin_or_lead
from crypto import decrypt_blob, encrypt_blob
from db.crud import create_incident, finalize_non_forensic_incident, set_exposure_end
from db.database import SessionLocal, get_db
from db.models import Project, User
from detector.match_resolver import resolve_match
from detector.scanner import scan
from pipeline import run_collection_pipeline
from notifications import notify_incident_created_by_id
from rag.index import index_incident_in_background
from window.calculator import is_key_revoked, record_exposure_start
from audit import record

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhook", tags=["webhook"])


def _run_initial_pipeline_and_notify(incident_id: str, credential: str, exposure_start: datetime, *, platform: str) -> None:
    """Run initial forensics, then notify using the persisted severity."""
    try:
        run_collection_pipeline(incident_id, credential, exposure_start, platform=platform)
    finally:
        notify_incident_created_by_id(incident_id)


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------

def _verify_signature(body: bytes, sig_header: str, secret: str) -> bool:
    """Return True if the X-Hub-Signature-256 header matches the HMAC of the body."""
    if not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig_header, expected)


def _encrypt_secret(secret: str) -> str:
    ciphertext, iv = encrypt_blob({"secret": secret})
    return f"{iv}.{ciphertext}"


def _decrypt_secret(value: str) -> str:
    iv, ciphertext = value.split('.', 1)
    return decrypt_blob(ciphertext, iv)["secret"]


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
        logger.warning("GitHub API error fetching diff (%s)", type(exc).__name__)
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
            logger.error("Revocation check failed for incident %s (%s)", incident_id, type(exc).__name__)
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

    # Only the repository name is used before signature verification.
    try:
        payload = json.loads(body)
        repo_full_name = payload.get("repository", {}).get("full_name", "")
        if not isinstance(repo_full_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repo_full_name):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, "Invalid GitHub webhook payload")
    matches = db.query(Project).filter(func.lower(Project.github_repo_full_name) == repo_full_name.lower(), Project.is_deleted.is_(False)).all()
    if not matches:
        logger.warning("Ignored webhook for an unregistered repository")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "project not found"})
    # A single-org deployment should have at most one matching project.
    if len(matches) != 1 or not matches[0].webhook_secret:
        raise HTTPException(401, "Webhook secret not configured")
    project = matches[0]
    try:
        project_secret = _decrypt_secret(project.webhook_secret)
    except Exception:
        raise HTTPException(503, "Project webhook secret is unavailable") from None

    # Verify the signature with the matched project's secret.
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(body, sig_header, project_secret):
        logger.error("[WEBHOOK FAIL] Signature mismatch")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Only process push events
    if event_type != "push":
        logger.info(f"[WEBHOOK] Ignored non-push event: {event_type}")
        return {"status": "ignored", "event": event_type}

    repo_url: str = project.github_repo_url
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
                project_id=project.id,
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
                    _run_initial_pipeline_and_notify,
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
                background_tasks.add_task(notify_incident_created_by_id, incident.incident_id)

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
    project_id: str
    webhook_url: str


class ManualSecretRequest(BaseModel):
    secret: str


@router.put("/projects/{project_id}/secret")
def set_manual_secret(project_id: str, body: ManualSecretRequest, request: Request,
                      user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    if not 16 <= len(body.secret) <= 128:
        raise HTTPException(422, "Webhook secret must contain 16 to 128 characters")
    try:
        project.webhook_secret = _encrypt_secret(body.secret)
    except Exception:
        raise HTTPException(503, "Webhook encryption is not configured") from None
    project.webhook_registered_at = None
    record(db, user, "project.webhook_secret_updated", request, project_id=project.id)
    db.commit()
    return {"message": "Webhook secret saved. Configure the same secret in GitHub."}


@router.post("/register", status_code=200)
async def register_webhook(body: RegisterRequest, request: Request,
                           user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    """Register a push hook for a project using its own encrypted secret."""
    project = assert_project_access(body.project_id, user, db)
    parsed = urlsplit(body.webhook_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path != "/webhook/github" or parsed.query or parsed.fragment):
        raise HTTPException(422, "Use an HTTPS webhook URL ending in /webhook/github")
    try:
        if not project.webhook_secret:
            project.webhook_secret = _encrypt_secret(secrets.token_urlsafe(32))
            db.commit()
        webhook_secret = _decrypt_secret(project.webhook_secret)
    except Exception:
        db.rollback()
        raise HTTPException(503, "Project webhook encryption is not configured") from None
    try:
        repo = Github(config.GITHUB_TOKEN).get_repo(project.github_repo_full_name)
        hooks = list(repo.get_hooks())
        hook = next((item for item in hooks if item.config.get("url", "") == body.webhook_url), None)
        hook_config = {"url": body.webhook_url, "content_type": "json", "secret": webhook_secret, "insecure_ssl": "0"}
        already_existed = hook is not None
        if hook:
            hook.edit(name="web", config=hook_config, events=["push"], active=True)
        else:
            hook = repo.create_hook(name="web", config=hook_config, events=["push"], active=True)
    except GithubException as exc:
        if exc.status == 403:
            detail = "GitHub denied access. Check the token's repository administration permissions."
        else:
            detail = "GitHub rejected the request. Check repository access and webhook settings."
        raise HTTPException(400, detail) from None
    project.webhook_registered_at = datetime.now(timezone.utc)
    record(db, user, "project.webhook_registered", request, project_id=project.id)
    db.commit()
    return {"success": True, "already_existed": already_existed, "webhook_id": hook.id,
            "message": "Project webhook registered on GitHub"}


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
        "environment": config.ENVIRONMENT,
    }
