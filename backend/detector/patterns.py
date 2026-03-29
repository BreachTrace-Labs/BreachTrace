import re
from dataclasses import dataclass
from typing import Sequence

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
