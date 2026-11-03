"""
Rule-based parsing of a natural-language question into incident filters.

No model: platforms, severities, impact categories and time ranges come from
a small vocabulary that is easy to enumerate, and a rule either matches or it
does not — it cannot invent a filter. Every value is checked against the same
sets the database uses before any query runs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from db.models import VALID_PLATFORMS
from detector.ai_keys import RULES as AI_RULES

# Alias -> platform. Matched as whole words, longest first.
PLATFORM_ALIASES: dict[str, str] = {
    "aws": "aws", "amazon": "aws", "s3": "aws", "ec2": "aws", "cloudtrail": "aws",
    "gcp": "gcp", "google cloud": "gcp", "google": "gcp", "gcs": "gcp", "firebase": "gcp",
    "azure": "azure", "microsoft": "azure",
    "stripe": "stripe",
    "twilio": "twilio", "sms": "twilio",
    "github": "github", "personal access token": "github", "pat": "github",
    "slack": "slack", "npm": "npm", "sendgrid": "sendgrid",
    "hugging face": "huggingface", "huggingface": "huggingface",
    "database": "db", "postgres": "db", "postgresql": "db", "mysql": "db",
    "mongodb": "db", "redis": "db", "connection string": "db",
}
PLATFORM_ALIASES.update({rule.provider: rule.provider for rule in AI_RULES})
PLATFORM_ALIASES.update({"claude": "anthropic", "gpt": "openai", "chatgpt": "openai",
                         "grok": "xai", "sarvam ai": "sarvam", "google gemini": "gemini",
                         "google api key": "googleai", "azure openai": "azureopenai"})

SEVERITY_WORDS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Phrase -> impact category (must be a classifier category).
CATEGORY_ALIASES: dict[str, str] = {
    "privilege escalation": "privilege_escalation", "escalation": "privilege_escalation",
    "new keys": "privilege_escalation", "persistence": "privilege_escalation",
    "exfiltration": "exfiltration", "exfiltrated": "exfiltration", "data theft": "exfiltration",
    "data access": "data_access", "data accessed": "data_access",
    "financial abuse": "financial_abuse", "fraud": "financial_abuse", "charges": "financial_abuse",
    "payouts": "financial_abuse", "money": "financial_abuse",
    "resource abuse": "resource_abuse", "crypto mining": "resource_abuse", "mining": "resource_abuse",
    "instances launched": "resource_abuse",
    "communication abuse": "communication_abuse", "spam": "communication_abuse",
    "sms pumping": "communication_abuse", "messages sent": "communication_abuse",
    "reconnaissance": "reconnaissance", "recon": "reconnaissance",
}
VALID_CATEGORIES = frozenset(CATEGORY_ALIASES.values())

# Words that mean the user wants their incident list, not a how-to answer.
_INCIDENT_WORDS = re.compile(
    r"\b(incidents?|leaks?|leaked|alerts?|detections?|exposures?|exposed|show|list|which|how many|my keys?|my credentials?)\b",
    re.IGNORECASE,
)
_HOW_TO = re.compile(r"^\s*(how|why|what is|what are|what does|explain|should|can i|do i)\b", re.IGNORECASE)
_OPEN = re.compile(r"\b(open|unrevoked|not revoked|still exposed|still open|active)\b", re.IGNORECASE)
_INCIDENT_ID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)


@dataclass
class ParsedQuery:
    text: str
    platforms: list[str] = field(default_factory=list)
    severity_min: int | None = None
    categories: list[str] = field(default_factory=list)
    date_from: datetime | None = None
    date_to: datetime | None = None
    open_only: bool = False
    incident_ids: list[str] = field(default_factory=list)
    wants_incidents: bool = False

    @property
    def has_filters(self) -> bool:
        return bool(
            self.platforms or self.severity_min or self.categories or self.date_from
            or self.date_to or self.open_only or self.incident_ids
        )

    def describe(self) -> dict:
        return {
            "platforms": self.platforms,
            "severity_min": self.severity_min,
            "categories": self.categories,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "open_only": self.open_only,
            "incident_ids": self.incident_ids,
        }


def _find_aliases(text: str, aliases: dict[str, str]) -> list[str]:
    found: list[str] = []
    lowered = text.lower()
    for alias in sorted(aliases, key=len, reverse=True):
        if re.search(rf"(?<![\w-]){re.escape(alias)}(?![\w-])", lowered):
            value = aliases[alias]
            if value not in found:
                found.append(value)
            lowered = re.sub(rf"(?<![\w-]){re.escape(alias)}(?![\w-])", " ", lowered)
    return found


def _start_of_day(moment: datetime) -> datetime:
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def _parse_dates(text: str, now: datetime) -> tuple[datetime | None, datetime | None]:
    lowered = text.lower()
    today = _start_of_day(now)

    if re.search(r"\btoday\b", lowered):
        return today, None
    if re.search(r"\byesterday\b", lowered):
        return today - timedelta(days=1), today
    match = re.search(r"\b(?:last|past|previous)\s+(\d+)\s+(hour|day|week|month)s?\b", lowered)
    if match:
        n, unit = int(match.group(1)), match.group(2)
        delta = {"hour": timedelta(hours=n), "day": timedelta(days=n),
                 "week": timedelta(weeks=n), "month": timedelta(days=30 * n)}[unit]
        return now - delta, None
    if re.search(r"\bthis week\b", lowered):
        return today - timedelta(days=today.weekday()), None
    if re.search(r"\b(last|past|previous) week\b", lowered):
        start = today - timedelta(days=today.weekday() + 7)
        return start, start + timedelta(days=7)
    if re.search(r"\bthis month\b", lowered):
        return today.replace(day=1), None
    if re.search(r"\b(last|past|previous) month\b", lowered):
        end = today.replace(day=1)
        return (end - timedelta(days=1)).replace(day=1), end

    iso = r"(\d{4}-\d{2}-\d{2})"
    match = re.search(rf"\bbetween\s+{iso}\s+and\s+{iso}", lowered)
    if match:
        start = datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(match.group(2)).replace(tzinfo=timezone.utc) + timedelta(days=1)
        return start, end
    match = re.search(rf"\b(?:since|after|from)\s+{iso}", lowered)
    if match:
        return datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc), None
    match = re.search(rf"\b(?:before|until)\s+{iso}", lowered)
    if match:
        return None, datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
    match = re.search(rf"\bon\s+{iso}", lowered)
    if match:
        start = datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
        return start, start + timedelta(days=1)
    return None, None


def parse(question: str, now: datetime | None = None) -> ParsedQuery:
    now = now or datetime.now(timezone.utc)
    parsed = ParsedQuery(text=question.strip())

    parsed.platforms = [p for p in _find_aliases(question, PLATFORM_ALIASES) if p in VALID_PLATFORMS]
    parsed.categories = [c for c in _find_aliases(question, CATEGORY_ALIASES) if c in VALID_CATEGORIES]

    severities = [v for word, v in SEVERITY_WORDS.items() if re.search(rf"\b{word}\b", question, re.IGNORECASE)]
    if severities:
        parsed.severity_min = min(severities)

    parsed.date_from, parsed.date_to = _parse_dates(question, now)
    parsed.open_only = bool(_OPEN.search(question))
    parsed.incident_ids = [m.lower() for m in _INCIDENT_ID.findall(question)]

    # A how-to question that merely names a platform or category ("how do I
    # rotate a twilio token", "sms pumping protection") is a knowledge
    # question. Asking about incidents, or a time/severity/state filter, lists
    # incidents; platform and category then narrow that list.
    asks_incidents = bool(_INCIDENT_WORDS.search(question))
    has_incident_only_filter = bool(
        parsed.severity_min or parsed.date_from or parsed.date_to or parsed.open_only
        or parsed.incident_ids
    )
    is_how_to = bool(_HOW_TO.search(question))
    parsed.wants_incidents = has_incident_only_filter or (asks_incidents and not is_how_to)
    return parsed
