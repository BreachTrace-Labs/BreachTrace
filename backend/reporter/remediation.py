"""
Deterministic remediation checklist.

Built in code, never generated. A checklist is the part of a report someone
acts on directly, and an instruction that names a command that does not exist,
or skips "delete the key the attacker created", does real damage. So it comes
from the platform profile plus the impact categories actually observed, and is
identical whichever model writes the prose around it.

Items start with "☐" so pipeline._extract_remediation_steps() parses them.
"""
from __future__ import annotations

from reporter.profiles import get_profile

# (platform, category) -> step. "*" matches any platform.
_CATEGORY_STEPS: dict[tuple[str, str], str] = {
    # Privilege escalation — undo whatever persistence the attacker set up.
    ("aws", "privilege_escalation"):
        "Delete any IAM access keys, users, login profiles or policy attachments created during the exposure window",
    ("gcp", "privilege_escalation"):
        "Remove IAM bindings and service-account keys created during the exposure window",
    ("azure", "privilege_escalation"):
        "Remove role assignments and app credentials created during the exposure window",
    ("stripe", "privilege_escalation"):
        "Check Settings → Business → Bank accounts and payouts, and revert any changed payout destination or connected application",
    ("twilio", "privilege_escalation"):
        "Delete API keys and subaccounts created during the exposure window",
    # Resource abuse — stop the meter.
    ("aws", "resource_abuse"):
        "Terminate or delete resources created during the exposure window{resources}",
    ("gcp", "resource_abuse"):
        "Delete Compute Engine instances and other resources created during the exposure window{resources}",
    ("azure", "resource_abuse"):
        "Delete virtual machines and other resources created during the exposure window{resources}",
    ("stripe", "resource_abuse"):
        "Review customers, products and payment links changed during the exposure window{resources}",
    ("twilio", "resource_abuse"):
        "Restore any TwiML application or webhook URL that was changed during the exposure window",
    # Money.
    ("stripe", "financial_abuse"):
        "Refund or cancel fraudulent charges and payouts, and contact Stripe support about the affected transactions",
    ("twilio", "financial_abuse"):
        "Release phone numbers or short codes purchased during the exposure window",
    ("*", "financial_abuse"):
        "Review the billing dashboard for charges incurred during the exposure window",
    # Messaging abuse.
    ("twilio", "communication_abuse"):
        "Enable SMS Pumping Protection and restrict Geo Permissions to the countries you actually serve",
    # Data.
    ("*", "exfiltration"):
        "Determine what data was copied{resources} and whether it contains personal data — GDPR requires notification within 72 hours",
    ("*", "data_access"):
        "Check whether the data that was read{resources} contains personal or payment data",
}

_ALWAYS_LAST = (
    "Purge the credential from git history (rotation alone leaves it readable in past commits)",
    "Enable secret scanning on the repository to catch the next leak before it is pushed",
)


def _resource_suffix(resources: list[str]) -> str:
    return f" ({', '.join(resources[:3])})" if resources else ""


def build_remediation(facts: dict) -> list[str]:
    """Ordered checklist: revoke first, then category-specific clean-up, then hygiene."""
    platform = facts.get("platform", "aws")
    profile = get_profile(platform)
    steps = [f"Revoke the exposed credential now: {profile.revoke_command}"]

    resources_by_category: dict[str, list[str]] = {}
    for action in facts.get("actions", []):
        bucket = resources_by_category.setdefault(action.get("category") or "", [])
        bucket.extend(r for r in action.get("resources", []) if r not in bucket)

    for category in facts.get("categories", {}):
        template = _CATEGORY_STEPS.get((platform, category)) or _CATEGORY_STEPS.get(("*", category))
        if template:
            step = template.format(resources=_resource_suffix(resources_by_category.get(category, [])))
            if step not in steps:
                steps.append(step)

    steps.append(f"Review {profile.audit_log} for any further activity: {profile.review_command}")
    if facts.get("source_ips"):
        steps.append(f"Block or investigate the source IPs: {', '.join(facts['source_ips'][:3])}")
    steps.extend(_ALWAYS_LAST)

    return [f"☐ {step}" for step in steps]
