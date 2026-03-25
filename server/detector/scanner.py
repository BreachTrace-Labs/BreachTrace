"""
Scans a commit diff for leaked credentials.
Returns a list of CredentialMatch objects.
"""

from normalizer.schema import CredentialMatch
from detector.patterns import AWS_ACCESS_KEY_PATTERN, AWS_SECRET_KEY_PATTERN


def scan(diff_text: str) -> list[CredentialMatch]:
    """Scan diff text for AWS access keys. Returns matches found."""
    matches: list[CredentialMatch] = []
    lines = diff_text.splitlines()

    for i, line in enumerate(lines):
        key_match = AWS_ACCESS_KEY_PATTERN.search(line)
        if not key_match:
            continue

        access_key_id = key_match.group(1)

        # Validate: must be exactly 20 characters
        if len(access_key_id) != 20:
            continue

        # Look for the secret key on adjacent lines
        secret_key = None
        for offset in [1, -1, 2]:
            adj = i + offset
            if 0 <= adj < len(lines):
                secret_match = AWS_SECRET_KEY_PATTERN.search(lines[adj])
                if secret_match and len(secret_match.group(1)) == 40:
                    secret_key = secret_match.group(1)
                    break

        hint = access_key_id[:4] + "****" + access_key_id[-4:]

        matches.append(
            CredentialMatch(
                credential_type="aws_access_key",
                access_key_id=access_key_id,
                secret_key=secret_key,
                hint=hint,
                line_number=i + 1,
            )
        )

    return matches
