"""
Credential regex patterns — AWS only this week.
Each pattern is a compiled regex with a named group for the match.
"""

import re

# AWS Access Key ID: starts with AKIA, followed by exactly 16 uppercase alphanumeric chars
AWS_ACCESS_KEY_PATTERN = re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")

# AWS Secret Access Key: exactly 40 base-64 chars (often on the line after the key ID)
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")

CREDENTIAL_PATTERNS = {
    "aws_access_key": AWS_ACCESS_KEY_PATTERN,
}
