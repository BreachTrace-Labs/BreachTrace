import re
from dataclasses import dataclass

# AWS Access Key ID: starts with AKIA, followed by 16 uppercase alphanumeric chars
AWS_ACCESS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")

# AWS Secret Access Key: 40-char base64-like string that typically follows an access key
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


@dataclass
class CredentialMatch:
    credential_type: str   # e.g. 'aws_access_key'
    access_key_id: str     # The matched AKIA... key ID
    credential_hint: str   # Masked: 'AKIA****<last4>'
    raw_match: str         # Full matched string
    line_number: int | None = None
    context_line: str | None = None


def find_aws_access_keys(text: str) -> list[CredentialMatch]:
    """Scan text and return all AWS access key matches."""
    matches = []
    for m in AWS_ACCESS_KEY_PATTERN.finditer(text):
        key_id = m.group(0)
        hint = key_id[:4] + "****" + key_id[-4:]
        matches.append(
            CredentialMatch(
                credential_type="aws_access_key",
                access_key_id=key_id,
                credential_hint=hint,
                raw_match=key_id,
            )
        )
    return matches
