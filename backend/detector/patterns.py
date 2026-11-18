import re
from dataclasses import dataclass, field
from typing import Sequence

# =============================================================================
# GCP CREDENTIAL PATTERNS — RESEARCH NOTES (Yash, Day 1)
# =============================================================================
#
# GCP SERVICE ACCOUNT KEY (JSON file format):
# {
#   "type": "service_account",
#   "project_id": "my-project",
#   "private_key_id": "abc123...",
#   "client_email": "name@project.iam.gserviceaccount.com",
#   "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
# }
#
# PATTERN 1 — Primary anchor: client_email
#   Regex: [a-z0-9\-\.]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com
#   Why this is the anchor: the domain suffix `.iam.gserviceaccount.com` is
#   unique to GCP service accounts and cannot appear in legitimate non-GCP code.
#
# PATTERN 2 — Context confirmation: service_account type field
#   Regex: "type"\s*:\s*"service_account"
#   Purpose: reduces false positives — if client_email appears without this
#   nearby, it could be a coincidental email. Check within ±20 lines.
#
# PATTERN 3 — Private key ID extraction
#   Regex: "private_key_id"\s*:\s*"([a-f0-9]{40})"
#   Purpose: 40-char hex key ID used to identify which specific key was leaked
#   when a service account has multiple active keys.
#
# =============================================================================
# AZURE CREDENTIAL PATTERNS — RESEARCH NOTES (Yash, Day 1)
# =============================================================================
#
# PATTERN 4 — Azure Client ID (Service Principal / App Registration ID)
#   Regex: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
#   Standard UUID format. UUID alone is NOT sufficient — must appear near
#   context keywords (case-insensitive, within ±3 lines):
#     client_id, clientid, azure_client_id, appid, applicationid, tenantid
#
# PATTERN 5 — Azure Client Secret
#   Regex: [A-Za-z0-9\.\-_~]{34,}
#   Azure-generated secrets are 34–40+ chars. Must appear near keywords:
#     client_secret, clientsecret, azure_client_secret, password
#   Conservative char class to avoid matching unrelated long strings.
#
# PATTERN 6 — Azure Storage Connection String (self-contained, no context needed)
#   Regex: DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{64,};
#   The literal prefix is unique to Azure — no keyword context check required.
#   AccountKey is a base64-encoded 512-bit key (~88 chars with padding).
#
# =============================================================================

# AWS Access Key ID: a 4-char type prefix followed by 16 uppercase alphanumerics.
#
# The prefix set is taken from SecretBench's published pattern
# (`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`, TruffleHog-sourced). We
# previously matched AKIA only, which missed ASIA — STS temporary session
# credentials — despite those appearing constantly in leaked CI configs.
# CloudTrail LookupEvents queries by AccessKeyId identically for all of them.
AWS_KEY_ID_PREFIXES = ("AKIA", "ABIA", "ACCA", "ASIA")
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9/])((?:" + "|".join(AWS_KEY_ID_PREFIXES) + r")[0-9A-Z]{16})\b"
)

# AWS Secret Access Key: 40-char base64-like string, often appearing after "=" or ":"
AWS_SECRET_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+])")
SECRET_CONTEXT_KEYWORDS = (
    "secret",
    "aws_secret",
    "secret_key",
    "secretaccesskey",
    "secret_access_key",
    "aws_secret_access_key",
)
SECRET_CONTEXT_RADIUS = 2


@dataclass
class CredentialMatch:
    credential_type: str   # e.g. 'aws_access_key'
    access_key_id: str     # The matched AKIA... key ID
    credential_hint: str   # Masked: 'AKIA**<last4>'
    raw_match: str         # Full matched string
    line_number: int | None = None
    context_line: str | None = None


def mask_access_key_id(access_key_id: str) -> str:
    """Return the masked credential hint used across incidents and tests."""
    return f"{access_key_id[:4]}****{access_key_id[-4:]}"


def _context_window(lines: Sequence[str], index: int, radius: int) -> str:
    """Keep context within the file/hunk barriers inserted by the scanner."""
    lo, hi = max(0, index - radius), min(len(lines), index + radius + 1)
    for position in range(index - 1, lo - 1, -1):
        if lines[position] == "\x00":
            lo = position + 1
            break
    for position in range(index + 1, hi):
        if lines[position] == "\x00":
            hi = position
            break
    return "\n".join(lines[lo:hi])


def has_nearby_secret(lines: Sequence[str], index: int, *, radius: int = SECRET_CONTEXT_RADIUS) -> bool:
    """Check whether a secret-key-looking value appears within the shared context window."""
    search_context = _context_window(lines, index, radius)
    context_lower = search_context.lower()

    return any(keyword in context_lower for keyword in SECRET_CONTEXT_KEYWORDS) and bool(
        AWS_SECRET_KEY_PATTERN.search(search_context)
    )


def find_aws_credentials(text: str) -> list[CredentialMatch]:
    matches = []
    seen = set()
    lines = text.splitlines()

    for i, line in enumerate(lines):
        # 1. Look for the AKIA key first (The anchor)
        for m in AWS_ACCESS_KEY_PATTERN.finditer(line):
            key_id = m.group(0)
            if key_id in seen:
                continue
            seen.add(key_id)

            hint = mask_access_key_id(key_id)

            # 2. Check the shared secret-context rule used by both detectors.
            secret_found = has_nearby_secret(lines, i)

            raw_match = f"{key_id} @ line {i+1}"
            if secret_found:
                raw_match += " (secret nearby)"

            matches.append(
                CredentialMatch(
                    credential_type="aws_access_key",
                    access_key_id=key_id,
                    credential_hint=hint,
                    raw_match=raw_match,
                    line_number=i + 1,
                    context_line=line.strip(),
                )
            )
    return matches


# =============================================================================
# GCP — regex constants, dataclass, implementation
# =============================================================================

# Firebase admin SDK service accounts are always named
# `firebase-adminsdk-<5 chars>@<project>.iam.gserviceaccount.com`.
FIREBASE_SA_EMAIL_PATTERN = re.compile(
    r'firebase-adminsdk-[a-z0-9]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'
)

GCP_CLIENT_EMAIL_PATTERN = re.compile(
    r'(?<![a-z0-9.\-])[a-z0-9.\-]{1,64}@[a-z0-9\-]{1,63}\.iam\.gserviceaccount\.com'
)
# Evidence that the surrounding text carries KEY MATERIAL rather than merely
# naming a service account.
#
# This distinction is the whole point. A service-account email is an identifier,
# not a secret: it appears routinely in IAM policy bindings, Kubernetes
# manifests, Terraform outputs and documentation. The credential is the private
# key. Treating every `*.iam.gserviceaccount.com` string as a leak fires on
# every README that documents which account to grant a role to.
#
# Matched case-insensitively, and with '-' normalised to '_' so that
# `activate-service-account` and `service_account` both count.
GCP_SERVICE_ACCOUNT_CONTEXT = (
    '"type"',
    'service_account',
    'private_key',
    'private_key_id',
    'client_email',
    'credentials',
    # Environment-variable names that conventionally accompany a key file.
    'sa_email',
    'gcp_sa',
)
GCP_PRIVATE_KEY_ID_PATTERN = re.compile(
    r'"private_key_id"\s*:\s*"([a-f0-9]{40})"'
)

# Contexts that NAME a service account by well-known convention and never carry
# key material. Checked against the matching line and take priority over the
# key-material markers, because several of them literally contain the substring
# "service-account" and would otherwise satisfy the gate.
GCP_IDENTIFIER_ONLY_MARKERS = (
    'iam.gke.io/gcp-service-account',   # GKE Workload Identity annotation
    'serviceaccount:',                  # IAM policy binding member
    'serviceaccountname:',              # Kubernetes pod spec
    'iam.gke.io/service-account',       # older GKE annotation form
)
GCP_CONTEXT_RADIUS = 20


@dataclass
class GCPCredentialMatch:
    credential_type: str        # 'gcp_service_account'
    client_email: str           # matched service account email
    private_key_id: str | None  # 40-char hex key ID if present in diff
    credential_hint: str        # first 8 chars of email + '...'
    raw_match: str
    line_number: int | None = None



def _is_eligible(index: int, candidate_lines: set[int] | None) -> bool:
    """
    Whether a match found on line ``index`` should be reported.

    ``None`` means every line is eligible, which is what direct callers and unit
    tests want. The scanner passes the set of ADDED diff lines so that a commit
    which *removes* a credential — the remediation commit — does not re-fire the
    alarm. Context windows are still evaluated over the full text, so a key file
    whose surrounding lines are unchanged is still recognised.

    AWS already worked this way; GCP, Azure and the SaaS families did not.
    """
    return candidate_lines is None or index in candidate_lines


def find_gcp_credentials(
    text: str,
    candidate_lines: set[int] | None = None,
) -> list[GCPCredentialMatch]:
    matches = []
    seen: set[str] = set()
    lines = text.splitlines()

    for i, line in enumerate(lines):
        if not _is_eligible(i, candidate_lines):
            continue
        if ".iam.gserviceaccount.com" not in line or "@" not in line:
            continue
        for m in GCP_CLIENT_EMAIL_PATTERN.finditer(line):
            email = m.group(0)
            if email in seen:
                continue

            # Check surrounding lines for key-material evidence.
            context_block = _context_window(lines, i, GCP_CONTEXT_RADIUS)
            normalised_context = context_block.lower().replace("-", "_")
            context_confirmed = any(
                kw.lower().replace("-", "_") in normalised_context
                for kw in GCP_SERVICE_ACCOUNT_CONTEXT
            )

            # Well-known identifier-only syntax wins over the marker check: a
            # GKE Workload Identity annotation contains "gcp-service-account"
            # and would otherwise satisfy the gate while naming, not leaking.
            if any(marker in line.lower() for marker in GCP_IDENTIFIER_ONLY_MARKERS):
                continue

            # ENFORCE the gate. It was previously computed and then used only to
            # decorate raw_match, which left the documented Pattern-2 defence
            # completely inert: any service-account email anywhere — including a
            # README line — produced a collectable Tier-1 incident.
            if not context_confirmed:
                continue

            seen.add(email)

            # Extract private_key_id from the same context window if present
            key_id_match = GCP_PRIVATE_KEY_ID_PATTERN.search(context_block)
            private_key_id = key_id_match.group(1) if key_id_match else None

            hint = email[:8] + "..."
            raw_match = f"{email} @ line {i + 1}"
            if context_confirmed:
                raw_match += " (service_account context)"

            matches.append(GCPCredentialMatch(
                # Firebase admin SDK keys ARE GCP service account keys — same
                # file format, same Cloud Audit Logs. They are labelled
                # separately so the report names the product the developer
                # actually recognises, while CREDENTIAL_TYPE_TO_PLATFORM still
                # routes them to the GCP collector. A free extra platform.
                credential_type=(
                    "firebase_service_account"
                    if FIREBASE_SA_EMAIL_PATTERN.match(email)
                    else "gcp_service_account"
                ),
                client_email=email,
                private_key_id=private_key_id,
                credential_hint=hint,
                raw_match=raw_match,
                line_number=i + 1,
            ))

    return matches


# =============================================================================
# AZURE — regex constants, dataclass, implementation
# =============================================================================

AZURE_CLIENT_ID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)
AZURE_CLIENT_ID_CONTEXT_KEYWORDS = (
    'client_id', 'clientid', 'azure_client_id', 'appid', 'applicationid',
    # Hyphenated CLI flag forms. Credentials appear in shell scripts and CI
    # configs as `--client-id <uuid>`, which the underscore-only list missed
    # entirely (S3-Y3 measured this as 2 of 2 Azure false negatives).
    'client-id', 'app-id', 'azure-client-id',
    # `az ad sp create-for-rbac` prints a service principal to stdout and is a
    # strong Azure signal on its own, even when the flag is only `--id`.
    'create-for-rbac', 'az ad sp',
)
# Azure AD client secrets issued since 2021 carry a distinctive shape: a short
# prefix, a literal '~', then ~30 more characters (commonly '<3 chars>8Q~...').
# Requiring the tilde is what makes this pattern specific.
#
# The previous form, `[A-Za-z0-9.\-_~]{34,}` gated only on a nearby keyword,
# matched ANY long string sitting near the word "password" — JWTs, bcrypt
# hashes, SMTP and Redis passwords, even other vendors' API keys. S3-Y3 measured
# that at 8 false positives on 8 adversarial samples: precision 0.714.
#
# Tradeoff, stated rather than hidden: legacy pre-2021 Azure secrets were plain
# base64 with no tilde and are no longer matched. That is a deliberate recall
# sacrifice — a missed credential yields no incident, while a false positive
# yields a bogus one and corrupts the Track A accuracy numbers.
AZURE_CLIENT_SECRET_PATTERN = re.compile(r'[A-Za-z0-9._~-]{2,8}~[A-Za-z0-9._~-]{25,40}')
AZURE_CLIENT_SECRET_CONTEXT_KEYWORDS = (
    'client_secret', 'clientsecret', 'azure_client_secret', 'password',
)
# Scenario fixtures label generated Azure credentials as AZ-RECON-01,
# AZ-DATA-01, etc. Recognize that explicit Azure-prefixed label when it is near
# an Azure-shaped client secret, while keeping the tilde secret signature as
# the required value pattern.
AZURE_SCENARIO_SECRET_LABEL = re.compile(r'\bAZ-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{2}\b', re.IGNORECASE)
AZURE_CONN_STRING_PATTERN = re.compile(
    r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{64,};'
)
AZURE_CONTEXT_RADIUS = 3
# Same-line label before a UUID that marks it as a non-sign-in identifier.
_AZURE_NON_PRINCIPAL_LABEL = re.compile(
    r'(tenant|subscription|directory|object)[_\- ]?(id)?\W*$|'
    r'(tenant|subscription|directory|object)[_\- ]?id["\']?\s*[:=]',
    re.IGNORECASE,
)


@dataclass
class AzureCredentialMatch:
    credential_type: str        # 'azure_service_principal' | 'azure_storage_connection'
    client_id: str | None       # UUID if service principal, None for connection strings
    credential_hint: str        # first 8 chars of client_id, or 'AZURE_CONN...'
    raw_match: str
    line_number: int | None = None
    secret_value: str | None = field(default=None, repr=False, compare=False)


def find_azure_credentials(
    text: str,
    candidate_lines: set[int] | None = None,
) -> list[AzureCredentialMatch]:
    matches = []
    seen: set[str] = set()
    lines = text.splitlines()

    # Connection strings are self-identifying — no context check needed
    for i, line in enumerate(lines):
        if not _is_eligible(i, candidate_lines):
            continue
        if "DefaultEndpointsProtocol=" not in line:
            continue
        for m in AZURE_CONN_STRING_PATTERN.finditer(line):
            conn_str = m.group(0)
            if conn_str in seen:
                continue
            seen.add(conn_str)
            matches.append(AzureCredentialMatch(
                credential_type="azure_storage_connection",
                client_id=None,
                credential_hint="AZURE_CONN...",
                raw_match=f"Azure storage connection string @ line {i + 1}",
                line_number=i + 1,
            ))

    # UUID-format client IDs require nearby Azure context keywords to avoid false positives
    for i, line in enumerate(lines):
        if not _is_eligible(i, candidate_lines):
            continue
        if line.count("-") < 4:
            continue
        for m in AZURE_CLIENT_ID_PATTERN.finditer(line):
            uuid = m.group(0).lower()
            if uuid in seen:
                continue

            context = _context_window(lines, i, AZURE_CONTEXT_RADIUS).lower()

            if not any(kw in context for kw in AZURE_CLIENT_ID_CONTEXT_KEYWORDS):
                continue  # UUID without Azure context — skip to avoid false positives

            # Tenant/subscription/object IDs sit beside the client ID in every
            # leaked SP config but are not a sign-in identity; treating them as
            # one creates a second incident whose forensics are always empty.
            if _AZURE_NON_PRINCIPAL_LABEL.search(line[:m.start()]):
                continue

            seen.add(uuid)
            hint = uuid[:8] + "..."
            matches.append(AzureCredentialMatch(
                credential_type="azure_service_principal",
                client_id=uuid,
                credential_hint=hint,
                raw_match=f"{uuid} @ line {i + 1}",
                line_number=i + 1,
            ))

    # Client secrets — require Azure keyword context; skip anything already caught as UUID/conn string
    for i, line in enumerate(lines):
        if not _is_eligible(i, candidate_lines):
            continue
        if "~" not in line:
            continue
        for m in AZURE_CLIENT_SECRET_PATTERN.finditer(line):
            secret = m.group(0)
            if secret in seen:
                continue

            context = _context_window(lines, i, AZURE_CONTEXT_RADIUS).lower()

            if (not any(kw in context for kw in AZURE_CLIENT_SECRET_CONTEXT_KEYWORDS)
                    and not AZURE_SCENARIO_SECRET_LABEL.search(context)):
                continue

            seen.add(secret)
            matches.append(AzureCredentialMatch(
                credential_type="azure_client_secret",
                client_id=None,
                credential_hint=secret[:8] + "...",
                raw_match=f"Azure client secret @ line {i + 1}",
                line_number=i + 1,
                secret_value=secret,
            ))

    return matches


# =============================================================================
# SaaS + TIER-2 CREDENTIALS — Sprint 3 (S3-Y5 / S3-Y6)
# =============================================================================
#
# Two-tier model (see plan.md §1). Not every credential type has an audit-log
# API a third party can query, so detection coverage and forensic coverage are
# deliberately different numbers:
#
#   Tier 1 — detected AND blast radius reconstructable from an audit log.
#   Tier 2 — detected only. No queryable per-credential audit log exists, so
#            BreachTrace reports the exposure window, credential class and a
#            remediation checklist, and states plainly why reconstruction is
#            impossible. `unavailable_reason` carries that text to the UI.
#
# All patterns below are anchored on a vendor-specific literal prefix, so
# unlike the Azure client-secret pattern they need no keyword context check.
# =============================================================================

TIER_FORENSIC = 1
TIER_DETECTION_ONLY = 2

# ── Tier 1 ────────────────────────────────────────────────────────────────────
# Published bound is 20-30; we required 24+, missing shorter live keys.
STRIPE_SECRET_KEY_PATTERN = re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,})\b")
TWILIO_ACCOUNT_SID_PATTERN = re.compile(r"\b(AC[0-9a-fA-F]{32})\b")
TWILIO_API_KEY_SID_PATTERN = re.compile(r"\b(SK[0-9a-fA-F]{32})\b")
TWILIO_AUTH_TOKEN_PATTERN = re.compile(r"(?<![0-9a-zA-Z])([0-9a-f]{32})(?![0-9a-zA-Z])")
TWILIO_CONTEXT_KEYWORDS = ("twilio", "auth_token", "authtoken", "account_sid", "accountsid")

# ── Tier 2 ────────────────────────────────────────────────────────────────────
# Published pattern allows a 36-255 char body; we had pinned exactly 36.
GITHUB_PAT_PATTERN = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")
GITHUB_FINE_GRAINED_PAT_PATTERN = re.compile(r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b")
SLACK_WEBHOOK_PATTERN = re.compile(
    r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{20,})"
)
# Published patterns cover xapp- (app-level tokens) alongside xox[baprs]-.
SLACK_TOKEN_PATTERN = re.compile(r"\b((?:xox[baprs]|xapp)-[0-9A-Za-z-]{10,})\b")
NPM_TOKEN_PATTERN = re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")
# Published bounds are 20-24 and 39-50; we had pinned the exact 22/43 form.
SENDGRID_API_KEY_PATTERN = re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50})\b")
HUGGINGFACE_TOKEN_PATTERN = re.compile(r"\b(hf_[A-Za-z0-9]{34})\b")
# Requires embedded credentials — a bare `postgres://localhost/db` is not a leak.
DB_CONNECTION_STRING_PATTERN = re.compile(
    r"\b((?:postgres|postgresql|mysql|mariadb|mongodb\+srv|mongodb|redis|amqp)://"
    r"[^:@/\s]+:[^@/\s]+@[^\s/\"']+)"
)

# Values that look like credentials but are documentation placeholders. Checked
# case-insensitively as substrings of the *secret* portion of a match.
_PLACEHOLDER_MARKERS = (
    "xxxx", "your", "example", "placeholder", "changeme", "redacted",
    "insert", "dummy", "sample", "<", ">", "abcdef123456", "0123456789",
)

# Passwords compared by exact match, not substring: a real password may legitimately
# contain "pass" or "test", and a real username may contain "user" ("appuser").
_PLACEHOLDER_PASSWORDS = frozenset({
    "password", "passwd", "pass", "secret", "changeme", "change_me", "changeit",
    "yourpassword", "your_password", "mypassword", "test", "admin", "root",
    "letmein", "hunter2", "todo", "fixme", "none", "null", "empty",
})

_REASON_NO_TOKEN_AUDIT_LOG = (
    "GitHub exposes per-token audit logs only to Enterprise organisations. "
    "Activity performed with a personal access token cannot be reconstructed."
)
_REASON_SLACK = (
    "Slack records incoming-webhook and bot activity in audit logs only on "
    "Enterprise Grid plans. Messages sent with this credential cannot be listed."
)
_REASON_NPM = "npm publishes no per-token audit API, so package actions cannot be listed."
_REASON_SENDGRID = (
    "SendGrid's Email Activity API is a paid add-on and is not queryable on the "
    "free tier, so sent mail cannot be enumerated."
)
_REASON_HUGGINGFACE = "Hugging Face exposes no audit API for access tokens."
_REASON_DB = (
    "Forensic reconstruction depends on audit logging inside the target database, "
    "which BreachTrace does not control and usually cannot reach."
)


@dataclass
class SaaSCredentialMatch:
    """
    Uniform match type for every credential family added after AWS/GCP/Azure.

    Deliberately one shape for all of them. The three original match classes each
    use a different identifier field (`access_key_id`, `client_email`, `client_id`),
    which is exactly why callers doing `match.access_key_id` raise AttributeError
    on a GCP match. New types share one contract so that cannot recur.
    """

    credential_type: str          # e.g. 'stripe_secret_key'
    platform: str                 # e.g. 'stripe' — selects collector + taxonomy
    principal: str | None         # identifier a collector queries by; None for Tier 2
    credential_hint: str          # masked, safe to log and display
    forensic_tier: int            # TIER_FORENSIC | TIER_DETECTION_ONLY
    raw_match: str
    line_number: int | None = None
    unavailable_reason: str | None = None   # populated for Tier 2 only
    detection_method: str | None = None
    confidence: str | None = None
    line_end: int | None = None


def mask_secret(value: str, *, keep_prefix: int = 8, keep_suffix: int = 4) -> str:
    """
    Mask a secret for display: keep a short leading prefix (which identifies the
    vendor) and the last few characters (which let a developer recognise *which*
    of their keys leaked), and elide everything in between.
    """
    if len(value) <= keep_prefix + keep_suffix:
        return value[:keep_prefix] + "****"
    return f"{value[:keep_prefix]}****{value[-keep_suffix:]}"


_URI_CREDENTIALS_PATTERN = re.compile(
    r"^[a-z+]+://([^:@/\s]+):([^@/\s]+)@", re.IGNORECASE
)


def _looks_like_filler(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    # Long runs of a single repeated character, e.g. 'sk_live_aaaaaaaa…'
    body = re.sub(r"^[a-zA-Z]+_(?:live_|test_)?", "", value)
    return len(set(body)) <= 2 and len(body) >= 8


def _is_placeholder(value: str) -> bool:
    """
    True when a syntactically valid match is obviously documentation filler.

    For connection strings only the password is judged. Judging the whole URI
    gets it backwards in both directions: a hostname like `db.internal.example`
    would reject a genuine credential, while the real giveaway — a password of
    literally "password" — sits outside any marker.
    """
    uri = _URI_CREDENTIALS_PATTERN.match(value)
    if uri:
        password = uri.group(2)
        return password.lower() in _PLACEHOLDER_PASSWORDS or _looks_like_filler(password)
    return _looks_like_filler(value)


# (credential_type, platform, pattern, tier, unavailable_reason)
_SAAS_PATTERN_SPECS: tuple[tuple[str, str, re.Pattern[str], int, str | None], ...] = (
    ("stripe_secret_key",     "stripe",      STRIPE_SECRET_KEY_PATTERN,        TIER_FORENSIC,       None),
    ("github_pat",            "github",      GITHUB_PAT_PATTERN,               TIER_DETECTION_ONLY, _REASON_NO_TOKEN_AUDIT_LOG),
    ("github_pat",            "github",      GITHUB_FINE_GRAINED_PAT_PATTERN,  TIER_DETECTION_ONLY, _REASON_NO_TOKEN_AUDIT_LOG),
    ("slack_webhook",         "slack",       SLACK_WEBHOOK_PATTERN,            TIER_DETECTION_ONLY, _REASON_SLACK),
    ("slack_token",           "slack",       SLACK_TOKEN_PATTERN,              TIER_DETECTION_ONLY, _REASON_SLACK),
    ("npm_token",             "npm",         NPM_TOKEN_PATTERN,                TIER_DETECTION_ONLY, _REASON_NPM),
    ("sendgrid_api_key",      "sendgrid",    SENDGRID_API_KEY_PATTERN,         TIER_DETECTION_ONLY, _REASON_SENDGRID),
    ("huggingface_token",     "huggingface", HUGGINGFACE_TOKEN_PATTERN,        TIER_DETECTION_ONLY, _REASON_HUGGINGFACE),
    ("db_connection_string",  "db",          DB_CONNECTION_STRING_PATTERN,     TIER_DETECTION_ONLY, _REASON_DB),
)

# Necessary literal substrings, used only to avoid regex work on unrelated source.
_SAAS_ANCHORS = {
    STRIPE_SECRET_KEY_PATTERN: ("sk_", "rk_"),
    GITHUB_PAT_PATTERN: ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    GITHUB_FINE_GRAINED_PAT_PATTERN: ("github_pat_",),
    SLACK_WEBHOOK_PATTERN: ("https://hooks.slack.com/services/",),
    SLACK_TOKEN_PATTERN: ("xox", "xapp-"), NPM_TOKEN_PATTERN: ("npm_",),
    SENDGRID_API_KEY_PATTERN: ("SG.",), HUGGINGFACE_TOKEN_PATTERN: ("hf_",),
    DB_CONNECTION_STRING_PATTERN: ("://",),
}


def _find_twilio_credentials(
    lines: Sequence[str],
    candidate_lines: set[int] | None = None,
) -> list[SaaSCredentialMatch]:
    """
    Twilio Account SIDs are self-identifying (`AC` + 32 hex), so the SID anchors
    the match. The auth token is a bare 32-char hex string with no prefix of its
    own — it is only reported when it sits near Twilio context keywords, the same
    discipline the AWS secret-key detector uses.
    """
    matches: list[SaaSCredentialMatch] = []
    seen: set[str] = set()

    for index, line in enumerate(lines):
        if not _is_eligible(index, candidate_lines):
            continue
        if "AC" not in line:
            continue
        for match in TWILIO_ACCOUNT_SID_PATTERN.finditer(line):
            account_sid = match.group(1)
            if account_sid in seen or _is_placeholder(account_sid):
                continue

            context = _context_window(lines, index, SECRET_CONTEXT_RADIUS)
            context_lower = context.lower()

            has_keyword = any(kw in context_lower for kw in TWILIO_CONTEXT_KEYWORDS)
            token_found = any(
                token_match.group(1) != account_sid[2:]
                for token_match in TWILIO_AUTH_TOKEN_PATTERN.finditer(context)
            )
            paired = has_keyword and token_found

            # ENFORCE the keyword gate. It was previously computed and then used
            # only to decorate raw_match, so any `AC` + 32 hex characters became
            # a Twilio incident — a UUID-free correlation id, a truncated hash,
            # any 34-char hex string beginning AC.
            #
            # The keyword is required, not the token: an Account SID is a public
            # identifier and the auth token is the actual secret, but a `.env`
            # naming TWILIO_ACCOUNT_SID is a genuine exposure even when the
            # token lives in another file. `paired` still records the stronger
            # signal for the report.
            if not has_keyword:
                continue

            seen.add(account_sid)

            raw = f"{account_sid} @ line {index + 1}"
            if paired:
                raw += " (auth token nearby)"

            matches.append(
                SaaSCredentialMatch(
                    credential_type="twilio_account_sid",
                    platform="twilio",
                    principal=account_sid,
                    credential_hint=mask_secret(account_sid),
                    forensic_tier=TIER_FORENSIC,
                    raw_match=raw,
                    line_number=index + 1,
                )
            )

    # API-key SIDs identify a key, not its owning account. Only associate an
    # account when exactly one Account SID appears in the same file/hunk context.
    # Never use the leaked secret for collection or persist it in the match.
    for index, line in enumerate(lines):
        if not _is_eligible(index, candidate_lines) or "SK" not in line:
            continue
        context = _context_window(lines, index, SECRET_CONTEXT_RADIUS)
        lower = context.lower()
        if not (any(word in lower for word in ("twilio", "api_key", "apikey", "api key"))
                or ("sid" in lower and "secret" in lower)):
            continue
        for found in TWILIO_API_KEY_SID_PATTERN.finditer(line):
            key_sid = found.group(1)
            if key_sid in seen or _is_placeholder(key_sid):
                continue
            seen.add(key_sid)
            accounts = set(TWILIO_ACCOUNT_SID_PATTERN.findall(context))
            account = next(iter(accounts)) if len(accounts) == 1 else None
            matches.append(SaaSCredentialMatch(
                credential_type="twilio_api_key", platform="twilio", principal=account,
                credential_hint=mask_secret(key_sid),
                forensic_tier=TIER_FORENSIC if account else TIER_DETECTION_ONLY,
                unavailable_reason=None if account else (
                    "Twilio API key SID detected without an unambiguous associated Account SID. "
                    "Identify the owning account and review its activity; a key SID alone does not identify it."
                ),
                raw_match=f"{mask_secret(key_sid)} @ line {index + 1}", line_number=index + 1,
            ))
    return matches


def find_saas_credentials(
    text: str,
    candidate_lines: set[int] | None = None,
    diagnostics: list[str] | None = None,
    *, ai_text: str | None = None,
) -> list[SaaSCredentialMatch]:
    """
    Scan text for every credential family beyond AWS/GCP/Azure.

    SaaS prefix patterns are self-identifying. Twilio uses local keyword context;
    AI matching additionally uses provider fields, static decoding and context.
    """
    matches: list[SaaSCredentialMatch] = []
    seen: set[str] = set()
    lines = text.splitlines()

    for index, line in enumerate(lines):
        if not _is_eligible(index, candidate_lines):
            continue
        for cred_type, platform, pattern, tier, reason in _SAAS_PATTERN_SPECS:
            if not any(anchor in line for anchor in _SAAS_ANCHORS[pattern]):
                continue
            for match in pattern.finditer(line):
                value = match.group(1)
                if value in seen or _is_placeholder(value):
                    continue
                seen.add(value)

                matches.append(
                    SaaSCredentialMatch(
                        credential_type=cred_type,
                        platform=platform,
                        # Tier 2 has nothing to query, so it carries no principal.
                        principal=value if tier == TIER_FORENSIC else None,
                        credential_hint=mask_secret(value),
                        forensic_tier=tier,
                        raw_match=f"{cred_type} @ line {index + 1}",
                        line_number=index + 1,
                        unavailable_reason=reason,
                    )
                )

    matches.extend(_find_twilio_credentials(lines, candidate_lines))
    from detector.ai_keys import find_candidates

    for found in find_candidates(ai_text if ai_text is not None else text, candidate_lines, diagnostics):
        if found.value in seen:
            continue
        seen.add(found.value)
        matches.append(SaaSCredentialMatch(
            credential_type=f"{found.provider}_api_key", platform=found.provider,
            principal=None, credential_hint=mask_secret(found.value),
            forensic_tier=TIER_DETECTION_ONLY,
            raw_match=f"{found.provider}_api_key @ line {found.start_line} ({found.method}; {found.confidence} confidence)",
            line_number=found.start_line, line_end=found.end_line,
            detection_method=found.method, confidence=found.confidence,
            unavailable_reason=(
                "BreachTrace detects this AI provider credential but does not "
                "collect its usage or attribute requests to it. Revoke the key "
                "and review usage and billing in the provider console. "
                f"Candidate detected using {found.method}; {found.confidence} confidence. "
                "Key validity and AI usage have not been verified."
            ),
        ))
    return matches
