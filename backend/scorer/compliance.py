"""Evidence-linked prompts for human review, not applicability or compliance decisions."""
from scorer.severity import check_gdpr_flag, check_pcidss_flag, check_soc2_flag


def compliance_review_flags(credential_type: str | None, events, *, forensic_tier: int = 1):
    flags = []
    if credential_type:
        flags.append({'id': 'owasp-nhi2', 'reason': 'A credential candidate was detected. Review secret-leakage guidance if it belongs to a non-human identity; its validity and identity ownership are not established.'})
    # Detection-only findings do not establish provider activity or compliance scope.
    observed = list(events) if forensic_tier != 2 else []
    if check_gdpr_flag(observed):
        flags.append({'id': 'gdpr-32-33', 'reason': 'An event classified as data access or exfiltration names a resource containing a personal-data keyword. The name alone does not establish personal data, access, a breach, or GDPR applicability.'})
    if check_pcidss_flag(observed):
        flags.append({'id': 'pci-incident-response', 'reason': 'A financial-activity classification or payment-related resource name appears in the collected events. This does not establish cardholder data, a cardholder-data environment, misuse, or PCI DSS scope.'})
    if check_soc2_flag(observed):
        flags.append({'id': 'soc2-security', 'reason': 'An event is classified as privilege escalation, exfiltration, or resource abuse. Review whether it relates to controls in your SOC 2 scope; the classification does not establish a control failure.'})
    return flags
