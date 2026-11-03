from __future__ import annotations

from dataclasses import dataclass
import re

from detector.patterns import (
    AWS_ACCESS_KEY_PATTERN,
    AzureCredentialMatch,
    CredentialMatch,
    GCPCredentialMatch,
    SaaSCredentialMatch,
    find_azure_credentials,
    find_gcp_credentials,
    find_saas_credentials,
    has_nearby_secret,
    mask_access_key_id,
)

AnyCredentialMatch = (
    CredentialMatch | GCPCredentialMatch | AzureCredentialMatch | SaaSCredentialMatch
)

_DIFF_METADATA_PREFIXES = ("diff --git", "index ", "@@")


@dataclass(frozen=True)
class _DiffLine:
    text: str
    original_line_number: int
    is_candidate: bool
    is_removed: bool = False
    source_group: int = 0


def _is_metadata_line(line: str) -> bool:
    return (line.startswith(_DIFF_METADATA_PREFIXES) or line.startswith(("--- ", "+++ "))
            or line == "\\ No newline at end of file")


def _normalize_diff_lines(diff_text: str) -> list[_DiffLine]:
    normalized: list[_DiffLine] = []
    source_group = 0

    for original_line_number, raw_line in enumerate(diff_text.splitlines(), start=1):
        if _is_metadata_line(raw_line):
            if raw_line.startswith(("diff --git", "@@")):
                source_group += 1
            continue

        if raw_line.startswith("+"):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=True,
                    source_group=source_group,
                )
            )
            continue

        if raw_line.startswith(" "):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=False,
                    source_group=source_group,
                )
            )
            continue

        if raw_line.startswith("-"):
            normalized.append(
                _DiffLine(
                    text=raw_line[1:],
                    original_line_number=original_line_number,
                    is_candidate=False,
                    is_removed=True,
                    source_group=source_group,
                )
            )
            continue

        normalized.append(
            _DiffLine(
                text=raw_line,
                original_line_number=original_line_number,
                is_candidate=True,
                source_group=source_group,
            )
        )

    return normalized


def scan(diff_text: str, *, include_saas: bool = False, source_format: str = "diff", diagnostics: list[str] | None = None) -> list[AnyCredentialMatch]:
    """
    Scan unified diff text for leaked credentials across AWS, GCP, and Azure.

    AWS: only added lines are checked (candidate lines).
    Context uses added/unchanged source within each file/hunk. Deleted material
    supplies no evidence. All returned line numbers refer to the input diff.

    ``include_saas`` adds the Stripe/Twilio/Tier-2 families. Both routers pass
    ``True``; they dispatch through ``detector.match_resolver.resolve_match`` and
    handle every match type. The default stays ``False`` so that callers which
    only expect the three cloud platforms — and the AWS-only unit tests — keep
    their existing behaviour.
    """
    matches: list[AnyCredentialMatch] = []
    seen: set[str] = set()
    if source_format not in {"diff", "text"}:
        raise ValueError("source_format must be diff or text")
    lines = (_normalize_diff_lines(diff_text) if source_format == "diff" else
             [_DiffLine(line, i, True) for i, line in enumerate(diff_text.splitlines(), start=1)])

    # Work on the post-commit source. Removed lines supply neither context nor
    # literals, and must not separate fragments that are now adjacent. Explicit
    # barriers isolate unrelated files/hunks without losing the original lines.
    source_lines = []
    previous_group = None
    for line in lines:
        if line.is_removed:
            continue
        if source_lines and line.source_group != previous_group:
            source_lines.append(_DiffLine("\x00", 0, False))
        source_lines.append(line)
        previous_group = line.source_group
    lines = source_lines
    source_text_lines = [line.text for line in lines]

    # AWS — candidate (added) lines only, existing behaviour unchanged
    for index, line in enumerate(lines):
        if not line.is_candidate:
            continue

        for match in AWS_ACCESS_KEY_PATTERN.finditer(line.text):
            access_key_id = match.group(1)
            if access_key_id in seen:
                continue

            seen.add(access_key_id)
            secret_found = has_nearby_secret(source_text_lines, index)
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

    # GCP / Azure / SaaS — the full stripped text is passed so that context
    # windows spanning UNCHANGED lines still resolve (a key file whose "type":
    # "service_account" line is context, not an addition).
    #
    # `candidate_lines` restricts which lines may *produce* a match to added
    # lines only. Without it the remediation commit that DELETES a leaked
    # credential re-fires the alarm for every platform except AWS, which had
    # always filtered correctly.
    stripped_text = "\n".join(source_text_lines)
    candidate_lines = {i for i, line in enumerate(lines) if line.is_candidate}

    contextual_matches: list[AnyCredentialMatch] = []
    contextual_matches.extend(find_gcp_credentials(stripped_text, candidate_lines))
    contextual_matches.extend(find_azure_credentials(stripped_text, candidate_lines))

    if include_saas:
        contextual_matches.extend(find_saas_credentials(stripped_text, candidate_lines, diagnostics))

    for match in contextual_matches:
        if match.line_number is not None and 0 < match.line_number <= len(lines):
            match.line_number = lines[match.line_number - 1].original_line_number
            match.raw_match = re.sub(r"(?<=@ line )\d+", str(match.line_number), match.raw_match)
        if isinstance(match, SaaSCredentialMatch) and match.line_end is not None and 0 < match.line_end <= len(lines):
            match.line_end = lines[match.line_end - 1].original_line_number
    matches.extend(contextual_matches)

    return matches


def scan_diff(diff_text: str, *, include_saas: bool = False) -> list[AnyCredentialMatch]:
    """Backward-compatible alias while the rest of the pipeline switches to `scan()`."""
    return scan(diff_text, include_saas=include_saas)


def scan_text(text: str, *, diagnostics: list[str] | None = None) -> list[AnyCredentialMatch]:
    """Whole-file scanning: leading +/- and diff headers are literal source."""
    return scan(text, include_saas=True, source_format="text", diagnostics=diagnostics)
