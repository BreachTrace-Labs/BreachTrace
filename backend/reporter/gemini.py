"""Gemini-based incident report generator."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Iterable, Sequence

import google.generativeai as genai

import config
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

_model: genai.GenerativeModel | None = None


# ---------------------------------------------------------------------------
# Platform profiles
# ---------------------------------------------------------------------------
# A report about a GCP leak that talks about S3 buckets and `aws iam` commands
# is worse than no report — it tells the reader to run commands that do not
# exist on their platform. Each profile supplies the vocabulary and the
# revocation command Gemini must use for that platform.

class _PlatformProfile:
    def __init__(
        self,
        *,
        name: str,
        audit_log: str,
        identity_term: str,
        vocabulary: str,
        revoke_command: str,
        review_command: str,
    ) -> None:
        self.name = name
        self.audit_log = audit_log
        self.identity_term = identity_term
        self.vocabulary = vocabulary
        self.revoke_command = revoke_command
        self.review_command = review_command


PLATFORM_PROFILES: dict[str, _PlatformProfile] = {
    "aws": _PlatformProfile(
        name="AWS",
        audit_log="CloudTrail",
        identity_term="access key ID",
        vocabulary=(
            "Use AWS terms only: S3 buckets and objects, EC2 instances, IAM users, "
            "roles and policies, regions. Never mention Cloud Storage, resource "
            "groups, service accounts or subscriptions."
        ),
        revoke_command="aws iam delete-access-key --access-key-id <KEY_ID>",
        review_command="aws cloudtrail lookup-events --lookup-attributes "
                       "AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>",
    ),
    "gcp": _PlatformProfile(
        name="Google Cloud",
        audit_log="Cloud Audit Logs",
        identity_term="service account email",
        vocabulary=(
            "Use Google Cloud terms only: Cloud Storage buckets and objects, Compute "
            "Engine instances, service accounts, IAM roles and bindings, projects, "
            "regions and zones. Never mention S3, EC2, access keys, resource groups "
            "or subscriptions."
        ),
        revoke_command="gcloud iam service-accounts keys delete <KEY_ID> "
                       "--iam-account=<SERVICE_ACCOUNT_EMAIL>",
        review_command='gcloud logging read \'protoPayload.authenticationInfo.'
                       'principalEmail="<SERVICE_ACCOUNT_EMAIL>"\'',
    ),
    "azure": _PlatformProfile(
        name="Microsoft Azure",
        audit_log="Activity Log",
        identity_term="client ID (app registration)",
        vocabulary=(
            "Use Azure terms only: storage accounts and blobs, virtual machines, "
            "service principals and app registrations, role assignments, resource "
            "groups, subscriptions and tenants. Never mention S3, EC2, IAM users, "
            "buckets or service account keys."
        ),
        revoke_command="az ad app credential delete --id <CLIENT_ID> --key-id <KEY_ID>",
        review_command="az monitor activity-log list --caller <CLIENT_ID>",
    ),
}

_DEFAULT_PLATFORM = "aws"


def _get_model() -> genai.GenerativeModel:
    """Return the Gemini model, initialising it on first use."""
    global _model
    if _model is None:
        genai.configure(api_key=config.GEMINI_API_KEY)
        _model = genai.GenerativeModel("gemma-3-27b-it")
    return _model


def _resolve_platform(
    platform: str | None,
    events: Sequence[ForensicEvent],
) -> str:
    """
    Work out which platform this report is about.

    Callers that know the platform pass it explicitly. When they do not, infer
    it from the events themselves rather than silently defaulting to AWS and
    emitting AWS vocabulary for a GCP or Azure incident.
    """
    if platform and platform.lower() in PLATFORM_PROFILES:
        return platform.lower()

    observed = Counter(
        (e.platform or "").lower()
        for e in events
        if (e.platform or "").lower() in PLATFORM_PROFILES
    )
    if observed:
        return observed.most_common(1)[0][0]

    return _DEFAULT_PLATFORM


def _format_event_line(event: ForensicEvent) -> str:
    src = event.event_source or "unknown-source"
    ip = event.source_ip or "unknown-ip"
    resource = event.affected_resource or "unspecified-resource"
    category = event.impact_category or "unclassified"
    ts = event.timestamp.isoformat()
    # Prefix cross-platform events so the narrative can attribute each action.
    prefix = f"[{(event.platform or 'aws').upper()}] "
    return f"{prefix}{ts} — {event.api_action} from {ip} on {resource} via {src} (category: {category})"


def _build_prompt(
    *,
    events: Iterable[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    affected_resources: list[str],
    source_ips: list[str],
    platform: str = _DEFAULT_PLATFORM,
) -> str:
    event_list = list(events)
    profile = PLATFORM_PROFILES.get(platform, PLATFORM_PROFILES[_DEFAULT_PLATFORM])

    event_lines = ["- " + _format_event_line(e) for e in event_list]
    events_block = (
        "\n".join(event_lines)
        if event_lines
        else f"- No {profile.audit_log} events were captured during the exposure window."
    )

    # A single leaked file can expose credentials for more than one platform.
    platforms_seen = sorted(
        {
            (e.platform or _DEFAULT_PLATFORM).lower()
            for e in event_list
            if (e.platform or "").lower() in PLATFORM_PROFILES
        }
    )
    multi_platform = len(platforms_seen) > 1

    stats = [
        f"Platform: {profile.name} ({profile.audit_log})",
        f"Overall severity: {overall_severity or 'UNKNOWN'}",
        f"Exposure duration: {exposure_duration_seconds}s",
        f"Unique affected resources: {', '.join(affected_resources) if affected_resources else 'none recorded'}",
        f"Source IPs observed: {', '.join(source_ips) if source_ips else 'none recorded'}",
    ]

    if multi_platform:
        other_names = ", ".join(
            PLATFORM_PROFILES[p].name for p in platforms_seen
        )
        stats.append(
            f"Cross-platform incident: activity was recorded on {other_names}. "
            "Attribute every action to the platform shown in its [TAG]."
        )
        vocabulary_rule = (
            "This incident spans multiple cloud platforms. Use each platform's own "
            "terminology when describing its events, and never attribute a resource "
            "to the wrong platform."
        )
        remediation_rule = (
            "Give separate remediation steps per platform, and state clearly that "
            "rotating one platform's credential does not remediate the other."
        )
    else:
        vocabulary_rule = profile.vocabulary
        remediation_rule = (
            f"Remediation must use {profile.name} commands. To revoke the credential "
            f"use the form: {profile.revoke_command}. To review further activity use: "
            f"{profile.review_command}"
        )

    context_block = "\n".join(f"- {line}" for line in stats)

    return f"""
You are a forensic incident responder. The audience is a developer with no security background. Avoid acronyms.
Keep the entire report under 400 words. Use exact resource names provided.

The leaked credential is identified by its {profile.identity_term}.

{vocabulary_rule}

Generate a forensic incident report in four sections:
1) Executive Summary — 1 paragraph, plain English, no jargon.
2) Chronological Narrative — what the attacker did step by step.
3) Business Impact Assessment.
4) Remediation Checklist — number each item, start with ☐, be specific and include exact resource names.
   {remediation_rule}

Context:
{context_block}

Events:
{events_block}
"""


def _fallback_report(
    *,
    events: Sequence[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    profile: _PlatformProfile,
) -> str:
    """
    Deterministic report used when Gemini is unavailable.

    Kept platform-correct: telling a Google Cloud user to "audit CloudTrail"
    is actively misleading, and this path runs during bulk experiment runs
    where Gemini is deliberately not called.
    """
    return "\n".join(
        [
            f"Automated summary — {profile.name} credential exposure.",
            "",
            f"Severity: {overall_severity or 'UNKNOWN'}",
            f"Exposure duration: {exposure_duration_seconds}s",
            f"Events recorded in {profile.audit_log}: {len(events)}",
            "",
            "Remediation checklist:",
            f"☐ Revoke the exposed credential: {profile.revoke_command}",
            f"☐ Review {profile.audit_log} for further activity: {profile.review_command}",
            "☐ Remove the credential from version control history and force-push the rewritten branch.",
        ]
    )


def generate_report(
    events: list[ForensicEvent],
    overall_severity: str,
    exposure_duration_seconds: int,
    affected_resources: list[str],
    source_ips: list[str],
    platform: str | None = None,
) -> str:
    """
    Call Gemini API to generate a plain-English forensic incident report.

    ``platform`` selects the vocabulary and remediation commands. When omitted
    it is inferred from the events, so callers that predate multi-platform
    support still produce a correctly-worded report.

    Fallback: returns a deterministic platform-correct summary when Gemini
    fails or no key is set.
    """
    resolved_platform = _resolve_platform(platform, events)
    profile = PLATFORM_PROFILES[resolved_platform]

    prompt = _build_prompt(
        events=events,
        overall_severity=overall_severity,
        exposure_duration_seconds=exposure_duration_seconds,
        affected_resources=affected_resources,
        source_ips=source_ips,
        platform=resolved_platform,
    )

    if not config.GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY not set — using deterministic report")
        return _fallback_report(
            events=events,
            overall_severity=overall_severity,
            exposure_duration_seconds=exposure_duration_seconds,
            profile=profile,
        )

    try:
        response = _get_model().generate_content(prompt)
        text = getattr(response, "text", None)
        if text and text.strip():
            return text.strip()
        logger.warning("Gemini returned an empty response — using fallback")
    except Exception:
        # Best-effort resilience — never block the pipeline on LLM failure.
        logger.exception("Gemini generation failed")

    return _fallback_report(
        events=events,
        overall_severity=overall_severity,
        exposure_duration_seconds=exposure_duration_seconds,
        profile=profile,
    )
