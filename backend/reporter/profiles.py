"""
Per-platform report vocabulary, blind spots and remediation commands.

Shared by every report path — the deterministic report, the local model and
the optional Gemini provider — and by the knowledge base, so the wording a user
reads in a report is the wording they find when they search.
"""

from __future__ import annotations

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
        blind_spot: str = "",
    ) -> None:
        self.name = name
        self.audit_log = audit_log
        self.identity_term = identity_term
        self.vocabulary = vocabulary
        self.revoke_command = revoke_command
        self.review_command = review_command
        # What this platform's audit log CANNOT see. Surfaced in the prompt so
        # the model cannot describe an empty result as "nothing happened".
        self.blind_spot = blind_spot


PLATFORM_PROFILES: dict[str, _PlatformProfile] = {
    "aws": _PlatformProfile(
        name="AWS",
        audit_log="CloudTrail",
        blind_spot=(
            "CloudTrail records management events reliably, but S3 and Lambda data events are only logged when data-event logging is explicitly enabled, which it often is not."
        ),
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
        blind_spot=(
            "Admin Activity logs are always on, but Data Access logs — which cover object reads — must be explicitly enabled per service and are off by default."
        ),
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
        blind_spot=(
            "The Azure Activity Log records control-plane operations only. Data-plane reads, such as downloading a blob, do not appear unless diagnostic settings were configured in advance."
        ),
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
    # Without these two, a Stripe or Twilio incident fell back to the AWS
    # profile and told the developer to run `aws iam delete-access-key`.
    "stripe": _PlatformProfile(
        name="Stripe",
        audit_log="Stripe Events",
        blind_spot=(
            "Stripe Events cover account activity, not activity attributed to this key. They record state changes, not read-only access, and the API only returns events from the last 30 days. An empty timeline does not prove the key was unused."
        ),
        identity_term="secret API key",
        vocabulary=(
            "Use Stripe terms only: charges, payment intents, refunds, payouts, "
            "customers, payment methods, bank accounts and the Dashboard. Never "
            "mention S3, EC2, IAM, buckets, instances or cloud regions."
        ),
        revoke_command="Stripe Dashboard → Developers → API keys → Roll key "
                       "(set the old key to expire now)",
        review_command="stripe events list --limit 100 "
                       "(or Dashboard → Developers → Events and Logs)",
    ),
    "twilio": _PlatformProfile(
        name="Twilio",
        audit_log="Twilio Messages, Calls and Monitor Events",
        blind_spot=(
            "Twilio Messages and Calls show account activity, not proof of use by a particular key. Monitor Events cover supported administrative changes. Reads of message history may leave no record; log permissions and retention limit coverage."
        ),
        identity_term="Account SID",
        vocabulary=(
            "Use Twilio terms only: messages (SMS), calls, phone numbers, the "
            "Account SID, the Auth Token and the Console. Never mention S3, EC2, "
            "IAM, buckets, instances or cloud regions."
        ),
        revoke_command="Twilio Console → Account → API keys & tokens → request a "
                       "secondary Auth Token, then promote it to primary",
        review_command="twilio api:core:messages:list and "
                       "twilio api:core:calls:list (or Console → Monitor → Logs)",
    ),
}

DEFAULT_PLATFORM = "aws"


def get_profile(platform: str | None) -> _PlatformProfile:
    """Profile for ``platform``, falling back to the default rather than raising."""
    return PLATFORM_PROFILES.get((platform or "").lower(), PLATFORM_PROFILES[DEFAULT_PLATFORM])
