"""
Build the knowledge base: hand-written playbooks plus sections generated from
the code itself.

Generating from the taxonomies, platform profiles, Tier-2 reasons and
compliance rules means search answers can never drift from what BreachTrace
actually does: change a severity in taxonomy_stripe.py and the knowledge base
changes with it on the next start.
"""
from __future__ import annotations

import re
from pathlib import Path

from classifier.taxonomy_aws import AWS_API_TAXONOMY
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from classifier.taxonomy_gcp import GCP_API_TAXONOMY
from classifier.taxonomy_stripe import STRIPE_API_TAXONOMY
from classifier.taxonomy_twilio import TWILIO_API_TAXONOMY
from detector import patterns
from reporter.facts import CATEGORY_LABELS, CATEGORY_ORDER
from reporter.profiles import PLATFORM_PROFILES
from scorer.severity import build_compliance_reasons

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

_TAXONOMIES = {
    "aws": AWS_API_TAXONOMY,
    "gcp": GCP_API_TAXONOMY,
    "azure": AZURE_API_TAXONOMY,
    "stripe": STRIPE_API_TAXONOMY,
    "twilio": TWILIO_API_TAXONOMY,
}
_SEVERITY_WORDS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Tier-2 credential types and the text explaining why nothing is collectable.
_TIER_TWO = {
    "GitHub personal access token": patterns._REASON_NO_TOKEN_AUDIT_LOG,
    "Slack webhook or token": patterns._REASON_SLACK,
    "npm token": patterns._REASON_NPM,
    "SendGrid API key": patterns._REASON_SENDGRID,
    "Hugging Face token": patterns._REASON_HUGGINGFACE,
    "database connection string": patterns._REASON_DB,
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


def _chunk(slug: str, title: str, text: str) -> dict:
    return {"id": f"kb:{slug}", "source_type": "kb", "source_id": slug, "title": title, "text": text}


def markdown_chunks() -> list[dict]:
    """One chunk per `## ` section of every file in knowledge/."""
    chunks = []
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        for section in re.split(r"^## ", path.read_text(encoding="utf-8"), flags=re.MULTILINE)[1:]:
            title, _, body = section.partition("\n")
            body = body.strip()
            if body:
                chunks.append(_chunk(f"{path.stem}-{_slug(title)}", title.strip(), body))
    return chunks


def taxonomy_chunks() -> list[dict]:
    """One chunk per (platform, category): the actions in it and what they mean."""
    chunks = []
    for platform, taxonomy in _TAXONOMIES.items():
        name = PLATFORM_PROFILES[platform].name
        by_category: dict[str, list[str]] = {}
        for action, entry in taxonomy.items():
            by_category.setdefault(entry["category"], []).append(
                f"{action} ({entry['label']}, {_SEVERITY_WORDS.get(entry['severity'], entry['severity'])})"
            )
        for category in sorted(by_category, key=lambda c: CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else 99):
            label = CATEGORY_LABELS.get(category, category)
            parts = _pack(sorted(by_category[category]))
            for n, items in enumerate(parts, start=1):
                suffix = f" (part {n} of {len(parts)})" if len(parts) > 1 else ""
                chunks.append(_chunk(
                    f"taxonomy-{platform}-{category}" + (f"-{n}" if len(parts) > 1 else ""),
                    f"{name} actions classified as {label}{suffix}",
                    f"BreachTrace classifies these {name} audit-log actions as {label}: "
                    + "; ".join(items) + ".",
                ))
    return chunks


# The embedding model reads ~512 tokens; longer chunks are only half-searchable.
_MAX_CHUNK_CHARS = 1500


def _pack(items: list[str]) -> list[list[str]]:
    """Group items into runs whose joined length stays under _MAX_CHUNK_CHARS."""
    groups: list[list[str]] = [[]]
    size = 0
    for item in items:
        if groups[-1] and size + len(item) > _MAX_CHUNK_CHARS:
            groups.append([])
            size = 0
        groups[-1].append(item)
        size += len(item) + 2
    return groups


def platform_chunks() -> list[dict]:
    chunks = []
    for platform, profile in PLATFORM_PROFILES.items():
        chunks.append(_chunk(
            f"platform-{platform}",
            f"{profile.name}: revoking the credential and reviewing {profile.audit_log}",
            f"For a leaked {profile.name} {profile.identity_term}, revoke it with: {profile.revoke_command}. "
            f"Review further activity with: {profile.review_command}. "
            f"What {profile.audit_log} cannot see: {profile.blind_spot}",
        ))
    for credential, reason in _TIER_TWO.items():
        chunks.append(_chunk(
            f"tier2-{_slug(credential)}",
            f"Why there is no activity timeline for a leaked {credential}",
            f"A leaked {credential} is a Tier 2 (detection-only) credential. {reason} "
            "BreachTrace records the exposure window and a remediation checklist. "
            "The missing timeline is not evidence the credential went unused.",
        ))
    return chunks


def compliance_chunks() -> list[dict]:
    chunks = []
    for name, flags in (
        ("GDPR", {"gdpr": True, "pcidss": False, "soc2": False}),
        ("PCI-DSS", {"gdpr": False, "pcidss": True, "soc2": False}),
        ("SOC 2", {"gdpr": False, "pcidss": False, "soc2": True}),
    ):
        text = " ".join(build_compliance_reasons(events=[], **flags))
        chunks.append(_chunk(f"compliance-{_slug(name)}", f"{name} obligations after a credential leak", text))
    return chunks


def build_kb_chunks() -> list[dict]:
    """Every knowledge-base chunk, ids unique."""
    chunks = markdown_chunks() + platform_chunks() + compliance_chunks() + taxonomy_chunks()
    ids = [c["id"] for c in chunks]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate knowledge-base ids: {sorted(duplicates)}")
    return chunks
