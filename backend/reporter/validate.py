"""
Grounding validator for generated report prose.

Used twice: to filter teacher outputs when building the distillation dataset,
and at runtime on every model-written report. Its job is to catch the failure
that matters most in a forensic report — stating something that is not in the
evidence — without needing another model to judge.

What it checks, against the fact sheet only:
  * IPs, ARNs, cloud/vendor identifiers and credential-shaped strings must
    appear in the facts;
  * money amounts must match a financial figure in the facts;
  * counts ("47 API calls") must match a count in the facts;
  * no other platform's vocabulary;
  * an empty incident must not be described as "unused" or "nothing happened".

Known limit, stated rather than hidden: an invented resource name with no digit,
underscore or slash and no quotes (e.g. production-backups) is not shape-
detectable. Distillation filtering plus the pairwise evaluation cover that gap.
"""
from __future__ import annotations

import json
import re

# Credential-shaped strings. A full secret in a report is a violation even if it
# were somehow present in the facts, which only ever carry masked hints.
_SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ARN = re.compile(r"\barn:[A-Za-z0-9\-]+:[^\s,;)\"'`]+")
# Identifier-shaped tokens: contain an underscore or slash, or mix digits with
# a separator. Catches i-0abc123, ch_3Nx…, users_export_2026.csv, SM…/CA… SIDs.
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-./:@+]*[A-Za-z0-9]")
_QUOTED = re.compile(r"[`\"“'‘]([^`\"”'’\n]{3,80})[`\"”'’]")
_AMOUNT = re.compile(
    r"(?:[$€£]\s?(\d[\d,]*(?:\.\d+)?))"
    r"|(?:(\d[\d,]*(?:\.\d+)?)\s?(?:USD|EUR|GBP|INR|CAD|AUD|JPY|dollars?)\b)",
    re.IGNORECASE,
)
_COUNT = re.compile(
    r"\b(\d[\d,]*)\s+(?:\w+\s)?(?:events?|calls?|API calls?|messages?|SMS|charges?|"
    r"transactions?|requests?|times|actions?|refunds?|payouts?|instances?|"
    r"resources?|attempts?|operations?)\b",
    re.IGNORECASE,
)
_UNUSED_CLAIMS = re.compile(
    r"\b(?:no (?:unauthori[sz]ed|malicious|suspicious) (?:activity|access|use)"
    r"|(?:was|were|has been|have been) (?:not|never) used"
    r"|(?:went|remained) unused"
    r"|nothing (?:happened|occurred|was done))\b",
    re.IGNORECASE,
)

_HEDGES = re.compile(
    r"not (?:prove|evidence|mean|guarantee|confirm|show)|doesn't (?:prove|mean)|cannot (?:prove|confirm)",
    re.IGNORECASE,
)

# Terms that belong to one platform only. A report on any other platform that
# uses them is mixing vocabularies — the failure test_report_platform_vocabulary
# pins for the template path.
_PLATFORM_TERMS: dict[str, tuple[str, ...]] = {
    "aws": ("S3", "EC2", "CloudTrail", "IAM user", "aws iam", "access key ID"),
    "gcp": ("Cloud Storage", "Compute Engine", "Cloud Audit Logs", "gcloud", "service account"),
    # Not bare "subscription": Stripe has subscriptions too.
    "azure": ("Activity Log", "resource group", "Azure subscription", "az ad", "app registration"),
    "stripe": ("payout", "Stripe"),
    "twilio": ("Twilio", "Auth Token", "Account SID"),
}

_MAX_WORDS = 450

# Activity words that assert something HAPPENED. Each needs a matching action in
# the facts. Caught in practice: an untuned model summarised a single charge as
# "charges, refunds, and payouts". Evidence is matched against action names and
# labels only — not the whole fact sheet, whose blind-spot text mentions
# refunds and payouts generically.
_ACTIVITY_CLAIMS: dict[str, tuple[str, ...]] = {
    r"\brefund(?:s|ed)?\b": ("refund",),
    r"\bpayouts?\b": ("payout",),
    r"\bdisputes?\b": ("dispute",),
    r"\bsubscriptions?\b": ("subscription",),
    r"\binvoices?\b": ("invoice",),
    r"\b(?:text )?messages? (?:were |was )?sent\b|\bsent \d[\d,]* messages?\b": ("message.",),
    r"\b(?:phone )?calls? (?:were |was )?(?:placed|made)\b": ("call.",),
    r"\b(?:launched|started|created) (?:\w+ )?(?:instances?|virtual machines?|VMs?)\b": ("instance", "virtualmachines"),
    r"\bbank accounts?\b": ("external_account", "bank"),
}
# Sentences about what the log can or cannot see are allowed to name activity
# generically ("Stripe Events record charges, refunds, payouts").
_GENERIC_SENTENCE = re.compile(r"\b(record|records|recorded|cannot|can't|only|not|no|blind)\b", re.IGNORECASE)

# Fact-sheet field names and raw category ids must not leak into prose.
_RAW_FIELDS = (
    "event_count", "failed_count", "first_event", "last_event", "other_action_count",
    "credential_hint", "credential_type", "platform_name", "audit_log", "blind_spot",
    "exposure_seconds", "severity_weight", "first_seen",
    "privilege_escalation", "financial_abuse", "resource_abuse", "communication_abuse",
    "data_access", "code_compromise",
)


def _fact_strings(facts: dict) -> str:
    """Every string in the fact sheet, lower-cased, as one searchable blob."""
    return json.dumps(facts, ensure_ascii=False).lower()


def _fact_numbers(facts: dict) -> set[float]:
    blob = json.dumps(facts, ensure_ascii=False)
    return {float(n.replace(",", "")) for n in re.findall(r"\d[\d,]*(?:\.\d+)?", blob)}


def _is_identifier(token: str) -> bool:
    has_digit = any(c.isdigit() for c in token)
    has_sep = any(c in "-./:" for c in token)
    return "_" in token or "/" in token or (has_digit and has_sep and not token.replace(".", "").replace(",", "").isdigit())


def _looks_like_time_or_date(token: str) -> bool:
    return bool(re.fullmatch(r"\d{1,4}([-/:.]\d{1,4}){1,3}", token))


def validate_sections(sections: dict, facts: dict) -> list[str]:
    """Return human-readable violations; an empty list means the prose is grounded."""
    violations: list[str] = []
    text = "\n".join(
        [sections.get("executive_summary", ""), *sections.get("narrative", []), sections.get("business_impact", "")]
    )
    known = _fact_strings(facts)
    numbers = _fact_numbers(facts)

    def unknown(token: str) -> bool:
        return token.lower().strip(".,:;") not in known

    for pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            violations.append(f"contains a credential-shaped string '{match.group(0)[:8]}…'")

    for ip in set(_IPV4.findall(text)):
        if unknown(ip):
            violations.append(f"IP address {ip} is not in the facts")

    for arn in set(_ARN.findall(text)):
        if unknown(arn):
            violations.append(f"ARN {arn} is not in the facts")

    candidates = {m.group(0) for m in _IDENTIFIER.finditer(text) if _is_identifier(m.group(0))}
    candidates |= {m.group(1).strip() for m in _QUOTED.finditer(text)}
    for token in sorted(candidates):
        if _IPV4.fullmatch(token) or _looks_like_time_or_date(token):
            continue
        if unknown(token):
            violations.append(f"'{token}' is not in the facts")

    for match in _AMOUNT.finditer(text):
        value = float((match.group(1) or match.group(2)).replace(",", ""))
        if not any(abs(value - n) < 0.011 for n in numbers):
            violations.append(f"amount {match.group(0).strip()} does not match any financial fact")

    for match in _COUNT.finditer(text):
        value = float(match.group(1).replace(",", ""))
        if value not in numbers:
            violations.append(f"count '{match.group(0)}' does not match any count in the facts")

    platform = facts.get("platform", "aws")
    for other, terms in _PLATFORM_TERMS.items():
        if other == platform:
            continue
        for term in terms:
            if re.search(rf"\b{re.escape(term)}\b", text, re.IGNORECASE if term.islower() else 0):
                violations.append(f"uses {other} vocabulary '{term}' in a {platform} report")

    if facts.get("event_count", 0) == 0:
        for match in _UNUSED_CLAIMS.finditer(text):
            # "this does not prove the credential went unused" is the CORRECT
            # statement; only an unhedged claim is a violation.
            if not _HEDGES.search(text[max(0, match.start() - 60): match.start()]):
                violations.append(
                    "claims the credential was unused; an empty audit log only means "
                    "no activity was recorded"
                )
                break

    evidence = " ".join(
        f"{a.get('action', '')} {a.get('label') or ''}" for a in facts.get("actions", [])
    ).lower()
    for sentence in re.split(r"(?<=[.!?])\s+|\n", text):
        if _GENERIC_SENTENCE.search(sentence):
            continue
        # Resource paths are identifiers, not claims: an Azure path contains
        # "/subscriptions/" without anything having been subscribed to.
        prose = re.sub(r"\S*/\S*", " ", sentence)
        for claim, needles in _ACTIVITY_CLAIMS.items():
            match = re.search(claim, prose, re.IGNORECASE)
            if match and not any(n in evidence for n in needles):
                violations.append(f"claims '{match.group(0)}' but no such action is in the facts")

    lowered = text.lower()
    for field in _RAW_FIELDS:
        if field in lowered:
            violations.append(f"leaks raw field name '{field}' — use plain words")

    if len(text.split()) > _MAX_WORDS:
        violations.append(f"too long ({len(text.split())} words, limit {_MAX_WORDS})")

    # Stable, de-duplicated order so retries and tests are deterministic.
    return list(dict.fromkeys(violations))
