"""
Legacy Gemini report generator (free-form prompt).

No longer called by the pipeline: reports are now built from a verified fact
sheet (reporter/facts.py) and written by the template or the local report model
(reporter/writers.py), with Gemini available there only as an optional writer
speaking the same structured contract. Kept for the vocabulary tests and the
research harness; PLATFORM_PROFILES now lives in reporter/profiles.py.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Iterable, Sequence

import config
from normalizer.schema import ForensicEvent
from reporter.profiles import PLATFORM_PROFILES, _PlatformProfile  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)

_model = None  # google.generativeai.GenerativeModel, created lazily

_DEFAULT_PLATFORM = "aws"


def _get_model():
    """
    Return the Gemini model, initialising it on first use.

    The SDK is imported here, not at module level: Gemini is optional (used for
    training-data generation), and the shipped app must import this module
    without it installed.
    """
    global _model
    if _model is None:
        import google.generativeai as genai

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

    # An empty result is the single most dangerous thing this report can
    # mishandle. Absence of logged activity is NOT evidence the credential went
    # unused: audit logs have documented blind spots, delivery delays, and in
    # Stripe's and Twilio's case record writes but not reads. Left to itself the
    # model writes "no unauthorised activity was detected", which is exactly the
    # false reassurance the whole system exists to eliminate.
    no_events_instruction = ""
    if not event_lines:
        no_events_instruction = (
            "\nCRITICAL — NO EVENTS WERE FOUND.\n"
            "You must NOT write that nothing happened, that the credential was "
            "unused, or that no unauthorised activity occurred. That is not what "
            "an empty result means.\n"
            f"State plainly that no activity was RECORDED in {profile.audit_log}, "
            "and that this is not the same as no activity having taken place. "
            f"Explain the limitation in plain language: {profile.blind_spot} "
            "Audit logs can also lag by several minutes.\n"
            "Treat the credential as compromised and keep the remediation "
            "checklist as urgent as it would be if activity had been found.\n"
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
{no_events_instruction}
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
    lines = [
        f"Automated summary — {profile.name} credential exposure.",
        "",
        f"Severity: {overall_severity or 'UNKNOWN'}",
        f"Exposure duration: {exposure_duration_seconds}s",
        f"Events recorded in {profile.audit_log}: {len(events)}",
    ]

    # Same rule as the Gemini path: an empty result must never read as
    # "nothing happened". This branch runs during bulk experiment runs, so it
    # is the wording that appears on most recorded incidents.
    if not events:
        lines += [
            "",
            f"No activity was RECORDED in {profile.audit_log}. This is NOT evidence "
            "that the credential went unused.",
            profile.blind_spot,
            "Treat the credential as compromised and complete every step below.",
        ]

    return "\n".join(
        lines
        + [
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
