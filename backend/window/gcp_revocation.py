"""
GCP service account key revocation check.

Attempts to refresh credentials using the leaked service account private key.
If the key has been disabled or deleted in IAM, Google's token endpoint returns
a 401/403 or raises a google.auth.exceptions.RefreshError → return True (revoked).

Falls back to False (cannot determine) when the private key is not available
in the environment (e.g. during unit tests without live GCP credentials).
"""
from __future__ import annotations

import logging

import config

logger = logging.getLogger(__name__)


def is_gcp_key_revoked(client_email: str, private_key_id: str) -> bool:
    """
    Attempt to use the leaked GCP service account key to refresh an OAuth2
    access token.  If the key is disabled or deleted, a RefreshError or
    TransportError is raised → return True (revoked).

    Parameters
    ----------
    client_email : str
        Service account email extracted from the leaked credential diff.
    private_key_id : str
        The 40-hex-char private_key_id from the service account JSON.

    Returns
    -------
    bool
        True  → key is confirmed revoked (auth failure).
        False → key is still active, OR revocation status cannot be determined
                (private key not available in env).
    """
    # The experiment private key is needed to attempt authentication.
    private_key: str = config.GCP_EXPERIMENT_PRIVATE_KEY
    if not private_key:
        logger.debug(
            "GCP_EXPERIMENT_PRIVATE_KEY not configured — "
            "cannot check revocation for %s",
            client_email[:30],
        )
        return False

    try:
        # Lazy imports so missing google-auth doesn't break startup.
        from google.auth.exceptions import RefreshError, TransportError  # type: ignore[import-untyped]
        from google.auth.transport.requests import Request  # type: ignore[import-untyped]
        from google.oauth2 import service_account  # type: ignore[import-untyped]

        creds = service_account.Credentials.from_service_account_info(
            {
                "type": "service_account",
                "client_email": client_email,
                "private_key_id": private_key_id,
                "private_key": private_key,
                "token_uri": "https://oauth2.googleapis.com/token",
            },
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        request = Request()
        creds.refresh(request)
        logger.debug(
            "[GCP ACTIVE] Service account %s key %s is still valid",
            client_email[:30],
            private_key_id[:8],
        )
        return False

    except Exception as exc:  # noqa: BLE001
        err = str(exc).lower()
        revoked_signals = (
            "invalid_grant",
            "key has been deleted",
            "key is disabled",
            "disabled",
            "401",
            "403",
            "unauthorized",
            "revoked",
            "expired",
        )
        if any(signal in err for signal in revoked_signals):
            logger.info(
                "[GCP REVOKED] Key %s for %s is revoked: %s",
                private_key_id[:8],
                client_email[:30],
                exc,
            )
            return True

        logger.warning(
            "GCP revocation check inconclusive for %s (key %s): %s",
            client_email[:30],
            private_key_id[:8],
            exc,
        )
        return False
