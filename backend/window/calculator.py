"""
Exposure window management: tracking when a credential becomes public until it's revoked.

Pipeline:
1. exposure_start = commit_timestamp (when credential leaked)
2. Background loop every 60s: check if key is revoked
3. When revoked: exposure_end = now()
4. If still active after 10 minutes: force close (experiment timeout)
"""

import asyncio
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

import config
from db.models import IncidentRecord

logger = logging.getLogger(__name__)  

# Timeout: close window after 10 minutes if not revoked
EXPOSURE_WINDOW_TIMEOUT_SECONDS = 600
REVOCATION_CHECK_INTERVAL_SECONDS = 60

# Track active monitoring tasks per incident
_active_monitors: dict[str, asyncio.Task] = {}

# AWS error codes when key is invalid/revoked
_REVOKED_ERROR_CODES = frozenset(
    {
        "InvalidClientTokenId",
        "InvalidAccessKeyId",
        "ExpiredTokenException",
    }
)


def record_exposure_start(commit_timestamp: str) -> datetime:
    """
    Parse commit timestamp and return UTC datetime.
    """
    return datetime.fromisoformat(commit_timestamp.replace("Z", "+00:00"))


def is_key_revoked(
    access_key_id: str,
    secret_access_key: str | None = None,
    *,
    admin_credentials: dict | None = None
) -> bool:
    """
    Check whether an AWS access key is revoked via STS GetCallerIdentity.

    When *secret_access_key* is provided the function authenticates as the
    leaked key directly — the most reliable way to detect revocation.
    Falls back to admin / configured credentials when the secret is unknown.
    """
    try:
        # Prefer leaked-key credentials when available
        if secret_access_key:
            access_key = access_key_id
            secret_key = secret_access_key
        elif admin_credentials:
            access_key = admin_credentials.get("access_key_id")
            secret_key = admin_credentials.get("secret_access_key")
        else:
            access_key = config.AWS_ACCESS_KEY_ID
            secret_key = config.AWS_SECRET_ACCESS_KEY

        client = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=config.AWS_REGION,
        )

        client.get_caller_identity()

        logger.debug(f"[ACTIVE] Key {access_key_id[:8]}...")
        return False

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]

        if error_code in _REVOKED_ERROR_CODES:
            logger.info(f"[REVOKED] Key {access_key_id[:8]}... ({error_code})")
            return True

        logger.warning(f"AWS error during revocation check: {error_code}")
        return False

    except Exception as e:
        logger.warning(f"Unexpected error checking key: {str(e)}")
        return False


def close_exposure_window(incident_id: str, db: Session) -> None:
    """
    Close exposure window by setting exposure_end.
    """
    incident = db.query(IncidentRecord).filter_by(incident_id=incident_id).first()

    if not incident:
        raise ValueError(f"Incident not found: {incident_id}")

    if incident.exposure_end is None:
        incident.exposure_end = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"Exposure window closed for incident {incident_id}")
    else:
        logger.debug(f"Exposure window already closed for {incident_id}")


async def monitor_exposure_window(
    incident_id: str,
    access_key_id: str,
    db_session: Session,
) -> None:
    """
    Background coroutine to monitor exposure window.
    """
    monitor_start = datetime.now(timezone.utc)

    logger.info(
        f"Starting monitor for incident {incident_id}, key {access_key_id[:8]}..."
    )

    while True:
        try:
            now = datetime.now(timezone.utc)
            elapsed_seconds = (now - monitor_start).total_seconds()

            # ⏱ Timeout condition
            if elapsed_seconds >= EXPOSURE_WINDOW_TIMEOUT_SECONDS:
                logger.warning(
                    f"Timeout reached ({EXPOSURE_WINDOW_TIMEOUT_SECONDS}s) "
                    f"for incident {incident_id}. Force closing."
                )
                close_exposure_window(incident_id, db_session)
                break

            # 🔐 Revocation check
            if is_key_revoked(access_key_id):
                logger.info(
                    f"Key revoked after {int(elapsed_seconds)}s → closing window"
                )
                close_exposure_window(incident_id, db_session)
                break

            await asyncio.sleep(REVOCATION_CHECK_INTERVAL_SECONDS)

        except asyncio.CancelledError:
            logger.info(f"Monitor cancelled for incident {incident_id}")
            break

        except Exception as e:
            logger.error(f"Monitor error: {e}")
            await asyncio.sleep(REVOCATION_CHECK_INTERVAL_SECONDS)

    logger.info(f"Monitor completed for incident {incident_id}")
    _active_monitors.pop(incident_id, None)


def start_window_monitor(
    incident_id: str,
    access_key_id: str,
    db_session: Session,
) -> None:
    """
    Start background monitoring task.
    """
    if incident_id in _active_monitors:
        logger.warning(f"Monitor already running for {incident_id}")
        return

    try:
        task = asyncio.create_task(
            monitor_exposure_window(incident_id, access_key_id, db_session)
        )
        _active_monitors[incident_id] = task

        logger.info(f"Monitor started for incident {incident_id}")

    except RuntimeError as e:
        logger.debug(f"No running event loop: {e}")


def stop_window_monitor(incident_id: str) -> None:
    """
    Stop monitoring task manually.
    """
    task = _active_monitors.get(incident_id)

    if task:
        task.cancel()
        _active_monitors.pop(incident_id, None)
        logger.info(f"Monitor stopped for incident {incident_id}")