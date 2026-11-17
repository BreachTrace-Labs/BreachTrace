"""Redact credential material from provider-supplied evidence."""
import re

_SENSITIVE_NAME = re.compile(r"(?:secret|password|authorization|private.?key|access.?token|api.?key|auth.?token|credential)", re.I)
_CREDENTIAL = re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]+\b|\bgh[pousr]_[A-Za-z0-9_]+\b|\bgithub_pat_[A-Za-z0-9_]+\b|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")


def redact(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SENSITIVE_NAME.search(str(key)) else redact(item)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _CREDENTIAL.sub("[REDACTED]", value)
    return value


def mask_identifier(value: str | None) -> str | None:
    return f"{value[:4]}****{value[-4:]}" if value and len(value) > 8 else ("[REDACTED]" if value else value)
