"""
Azure service principal revocation check.

Attempts to acquire an OAuth2 token using the leaked client_id + client_secret.
If Azure AD returns AADSTS7000215 (invalid secret), AADSTS7000222 (expired
secret), or any other ClientAuthenticationError → return True (revoked).

Falls back to False (cannot determine) when the tenant ID is not configured
or the client_secret is empty.
"""
from __future__ import annotations

import logging

import config

logger = logging.getLogger(__name__)


def is_azure_key_revoked(client_id: str, client_secret: str) -> bool:
    """
    Attempt to acquire a token for Azure Resource Manager using the leaked
    client credentials.  An authentication failure indicates the secret has
    been rotated or the application has been deleted → return True (revoked).

    Parameters
    ----------
    client_id : str
        Azure AD application (client) ID extracted from the leaked diff.
    client_secret : str
        The leaked client secret value.

    Returns
    -------
    bool
        True  → credential is confirmed revoked / invalid.
        False → credential is still active, OR status cannot be determined
                (tenant ID not configured, or secret not available).
    """
    tenant_id: str = config.AZURE_TENANT_ID or ""
    if not tenant_id or not client_secret:
        logger.debug(
            "AZURE_TENANT_ID or client_secret not available — "
            "cannot check revocation for client_id=%s",
            (client_id or "unknown")[:12],
        )
        return False

    try:
        # Lazy imports so missing azure-identity doesn't break startup.
        from azure.core.exceptions import ClientAuthenticationError  # type: ignore[import-untyped]
        from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]

        cred = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        # Request a token — this makes the real OIDC round-trip to Azure AD.
        cred.get_token("https://management.azure.com/.default")
        logger.debug("[AZURE ACTIVE] Client ID %s is still valid", client_id[:12])
        return False

    except Exception as exc:  # noqa: BLE001
        err_str = str(exc)
        # AADSTS7000215 — invalid client secret (rotated)
        # AADSTS7000222 — client secret expired
        # AADSTS700016  — application not found (deleted)
        # AADSTS50034   — user/tenant not found
        revoked_codes = (
            "AADSTS7000215",
            "AADSTS7000222",
            "AADSTS700016",
            "AADSTS50034",
            "ClientAuthenticationError",
            "invalid_client",
        )
        if any(code in err_str for code in revoked_codes):
            logger.info(
                "[AZURE REVOKED] Client %s is revoked: %.80s",
                client_id[:12],
                err_str,
            )
            return True

        logger.warning(
            "Azure revocation check inconclusive for client_id=%s: %s",
            client_id[:12],
            exc,
        )
        return False
