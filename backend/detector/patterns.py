import re
from dataclasses import dataclass

# AWS Access Key ID: starts with AKIA, followed by 16 uppercase alphanumeric chars
AWS_ACCESS_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/])(AKIA[0-9A-Z]{16})\b")

# AWS Secret Access Key: 40-char base64-like string, often appearing after "=" or ":"
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+])")
SECRET_CONTEXT_KEYWORDS = ("secret", "aws_secret", "access_key")


@dataclass
class CredentialMatch:
    credential_type: str   # e.g. 'aws_access_key'
    access_key_id: str     # The matched AKIA... key ID
    credential_hint: str   # Masked: 'AKIA**<last4>'
    raw_match: str         # Full matched string
    line_number: int | None = None
    context_line: str | None = None


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

            hint = f"{key_id[:4]}**{key_id[-4:]}"

            # 2. Extract context window (+/- 2 lines)
            context_lines = lines[max(0, i-2): min(len(lines), i+3)]
            search_context = "\n".join(context_lines)
            context_lower = search_context.lower()

            # 3. Fast-path: Only search for secret if context looks suspicious
            secret_found = False
            if any(k in context_lower for k in SECRET_CONTEXT_KEYWORDS):
                # Using the stronger regex from your first version
                if AWS_SECRET_KEY_PATTERN.search(search_context):
                    secret_found = True

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

