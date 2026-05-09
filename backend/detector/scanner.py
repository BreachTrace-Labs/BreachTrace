from __future__ import annotations

from dataclasses import dataclass

from detector.patterns import (
    AWS_ACCESS_KEY_PATTERN,
    AzureCredentialMatch,
    CredentialMatch,
    GCPCredentialMatch,
    find_azure_credentials,
    find_gcp_credentials,
    has_nearby_secret,
    mask_access_key_id,
)

_DIFF_METADATA_PREFIXES = ("diff --git", "index ", "@@")


@dataclass(frozen=True)
class _DiffLine:
    text: str
    original_line_number: int
    is_candidate: bool


def _is_metadata_line(line: str) -> bool:
    return line.startswith(_DIFF_METADATA_PREFIXES) or line.startswith("---") or line.startswith("+++")


def _normalize_diff_lines(diff_text: str) -> list[_DiffLine]:
    normalized: list[_DiffLine] = []

    for original_line_number, raw_line in enumerate(diff_text.splitlines(), start=1):
        if _is_metadata_line(raw_line):
            continue

        if raw_line.startswith("+"):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=True,
                )
            )
            continue

        if raw_line.startswith(" "):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=False,
                )
            )
            continue

        if raw_line.startswith("-"):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=False,
                )
            )
            continue

        normalized.append(
            _DiffLine(
                text=raw_line,
                original_line_number=original_line_number,
                is_candidate=True,
            )
        )

    return normalized


def _has_nearby_secret(lines: list[_DiffLine], index: int) -> bool:
    return has_nearby_secret([line.text for line in lines], index)


def scan(diff_text: str) -> list[CredentialMatch | GCPCredentialMatch | AzureCredentialMatch]:
    """
    Scan unified diff text for leaked credentials across AWS, GCP, and Azure.

    AWS: only added lines are checked (candidate lines).
    GCP/Azure: all stripped lines are passed so multi-line JSON key files and
    context windows spanning unchanged lines are handled correctly.
    """
    matches: list[CredentialMatch | GCPCredentialMatch | AzureCredentialMatch] = []
    seen: set[str] = set()
    lines = _normalize_diff_lines(diff_text)

    # AWS — candidate (added) lines only, existing behaviour unchanged
    for index, line in enumerate(lines):
        if not line.is_candidate:
            continue

        for match in AWS_ACCESS_KEY_PATTERN.finditer(line.text):
            access_key_id = match.group(1)
            if access_key_id in seen:
                continue

            seen.add(access_key_id)
            secret_found = _has_nearby_secret(lines, index)
            raw_match = f"{access_key_id} @ line {line.original_line_number}"
            if secret_found:
                raw_match += " (secret nearby)"

            matches.append(
                CredentialMatch(
                    credential_type="aws_access_key",
                    access_key_id=access_key_id,
                    credential_hint=mask_access_key_id(access_key_id),
                    raw_match=raw_match,
                    line_number=line.original_line_number,
                    context_line=line.text.strip(),
                )
            )

    # GCP + Azure — run on all diff lines stripped of markers so context windows
    # spanning unchanged lines are preserved for multi-line key file detection
    stripped_text = "\n".join(line.text for line in lines)
    matches.extend(find_gcp_credentials(stripped_text))
    matches.extend(find_azure_credentials(stripped_text))

    return matches


def scan_diff(diff_text: str) -> list[CredentialMatch]:
    """Backward-compatible alias while the rest of the pipeline switches to `scan()`."""
    return scan(diff_text)
