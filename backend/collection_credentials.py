"""Resolve provider readers for an incident without crossing project boundaries."""
from sqlalchemy.orm import Session

from crypto import decrypt_blob
from db.models import CredentialWalletEntry, IncidentRecord


class ReaderConfigurationError(ValueError):
    """A safe, user-visible reader configuration error."""


def project_reader(db: Session, incident: IncidentRecord, provider: str) -> dict | None:
    """Return the incident project's verified reader; None means a legacy incident.

    A missing or unusable project connection must not fall back to a global
    reader, which may belong to a different customer or account.
    """
    if not incident.project_id:
        return None
    entry = db.query(CredentialWalletEntry).filter_by(
        project_id=incident.project_id, provider=provider
    ).first()
    if entry is None:
        raise ReaderConfigurationError(
            f"Add a {provider.upper()} reader to this project's credential wallet before collecting activity."
        )
    if entry.verification_status != 'ok':
        raise ReaderConfigurationError(
            f"Verify the {provider.upper()} connection in this project's credential wallet before collecting activity."
        )
    try:
        values = decrypt_blob(entry.encrypted_blob, entry.iv)
        if not isinstance(values, dict):
            raise ValueError('Invalid wallet payload')
        return values
    except Exception:
        raise ReaderConfigurationError(
            f"The {provider.upper()} wallet connection could not be read. Check the wallet encryption key or replace the connection."
        ) from None
