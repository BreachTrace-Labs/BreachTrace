import re
from dataclasses import dataclass
from typing import Sequence

# =============================================================================
# GCP CREDENTIAL PATTERNS — RESEARCH NOTES (Yash, Day 1)
# =============================================================================
#
# GCP SERVICE ACCOUNT KEY (JSON file format):
# {
#   "type": "service_account",
#   "project_id": "my-project",
#   "private_key_id": "abc123...",
#   "client_email": "name@project.iam.gserviceaccount.com",
#   "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
# }
#
# PATTERN 1 — Primary anchor: client_email
#   Regex: [a-z0-9\-\.]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com
#   Why this is the anchor: the domain suffix `.iam.gserviceaccount.com` is
#   unique to GCP service accounts and cannot appear in legitimate non-GCP code.
#
# PATTERN 2 — Context confirmation: service_account type field
#   Regex: "type"\s*:\s*"service_account"
#   Purpose: reduces false positives — if client_email appears without this
#   nearby, it could be a coincidental email. Check within ±20 lines.
#
# PATTERN 3 — Private key ID extraction
#   Regex: "private_key_id"\s*:\s*"([a-f0-9]{40})"
#   Purpose: 40-char hex key ID used to identify which specific key was leaked
#   when a service account has multiple active keys.
#
# =============================================================================
# AZURE CREDENTIAL PATTERNS — RESEARCH NOTES (Yash, Day 1)
# =============================================================================
#
# PATTERN 4 — Azure Client ID (Service Principal / App Registration ID)
#   Regex: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
#   Standard UUID format. UUID alone is NOT sufficient — must appear near
#   context keywords (case-insensitive, within ±3 lines):
#     client_id, clientid, azure_client_id, appid, applicationid, tenantid
#
# PATTERN 5 — Azure Client Secret
#   Regex: [A-Za-z0-9\.\-_~]{34,}
#   Azure-generated secrets are 34–40+ chars. Must appear near keywords:
#     client_secret, clientsecret, azure_client_secret, password
#   Conservative char class to avoid matching unrelated long strings.
#
# PATTERN 6 — Azure Storage Connection String (self-contained, no context needed)
#   Regex: DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{64,};
#   The literal prefix is unique to Azure — no keyword context check required.
#   AccountKey is a base64-encoded 512-bit key (~88 chars with padding).
#
# =============================================================================

# AWS Access Key ID: starts with AKIA, followed by 16 uppercase alphanumeric chars
AWS_ACCESS_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/])(AKIA[0-9A-Z]{16})\b")

# AWS Secret Access Key: 40-char base64-like string, often appearing after "=" or ":"
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+])")
SECRET_CONTEXT_KEYWORDS = (
    "secret",
    "aws_secret",
    "secret_key",
    "secretaccesskey",
    "secret_access_key",
    "aws_secret_access_key",
)
SECRET_CONTEXT_RADIUS = 2


@dataclass
class CredentialMatch:
    credential_type: str   # e.g. 'aws_access_key'
    access_key_id: str     # The matched AKIA... key ID
    credential_hint: str   # Masked: 'AKIA**<last4>'
    raw_match: str         # Full matched string
    line_number: int | None = None
    context_line: str | None = None


def mask_access_key_id(access_key_id: str) -> str:
    """Return the masked credential hint used across incidents and tests."""
    return f"{access_key_id[:4]}****{access_key_id[-4:]}"


def has_nearby_secret(lines: Sequence[str], index: int, *, radius: int = SECRET_CONTEXT_RADIUS) -> bool:
    """Check whether a secret-key-looking value appears within the shared context window."""
    context_lines = lines[max(0, index - radius): min(len(lines), index + radius + 1)]
    search_context = "\n".join(context_lines)
    context_lower = search_context.lower()

    return any(keyword in context_lower for keyword in SECRET_CONTEXT_KEYWORDS) and bool(
        AWS_SECRET_KEY_PATTERN.search(search_context)
    )


def find_aws_credentials(text: str) -> list[CredentialMatch]:
    matches = []
    seen = set()
    lines = text.splitlines()

    for i, line in enumerate(lines):
        # 1. Look for the AKIA key first (The anchor)
        for m in AWS_ACCESS_KEY_PATTERN.finditer(line):
            key_id = m.group(0)
            if key_id in seen:
                continue
            seen.add(key_id)

            hint = mask_access_key_id(key_id)

            # 2. Check the shared secret-context rule used by both detectors.
            secret_found = has_nearby_secret(lines, i)

            raw_match = f"{key_id} @ line {i+1}"
            if secret_found:
                raw_match += " (secret nearby)"

            matches.append(
                CredentialMatch(
                    credential_type="aws_access_key",
                    access_key_id=key_id,
                    credential_hint=hint,
                    raw_match=raw_match,
                    line_number=i + 1,
                    context_line=line.strip(),
                )
            )
    return matches


# =============================================================================
# GCP — dataclass + stub (implementation: Day 2)
# =============================================================================

@dataclass
class GCPCredentialMatch:
    credential_type: str        # 'gcp_service_account'
    client_email: str           # matched service account email
    private_key_id: str | None  # 40-char hex key ID if present in diff
    credential_hint: str        # first 8 chars of email + '...'
    raw_match: str
    line_number: int | None = None


def find_gcp_credentials(text: str) -> list[GCPCredentialMatch]:
    # TODO Day 2: implement using GCP_CLIENT_EMAIL_PATTERN + context confirmation
    raise NotImplementedError


# =============================================================================
# AZURE — dataclass + stub (implementation: Day 2)
# =============================================================================

@dataclass
class AzureCredentialMatch:
    credential_type: str        # 'azure_service_principal' | 'azure_storage_connection'
    client_id: str | None       # UUID if detected
    credential_hint: str        # first 8 chars of client_id or 'AZURE_CONN...'
    raw_match: str
    line_number: int | None = None


def find_azure_credentials(text: str) -> list[AzureCredentialMatch]:
    # TODO Day 2: implement using UUID pattern + context keywords + connection string pattern
    raise NotImplementedError
