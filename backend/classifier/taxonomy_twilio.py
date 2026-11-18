"""Twilio taxonomy (S3-S4).

Keys are `resource.action` names, matching what the Twilio collector emits from
the Messages, Calls and Usage Records APIs:
  "message.sent", "call.created", "number.purchased"

Same dict shape as the other taxonomies:
  {action: {"category": str, "severity": int, "label": str}}

--------------------------------------------------------------------------
BULK THRESHOLD — Twilio needs its own, and this matters
--------------------------------------------------------------------------
classifier/rules.py escalates data_access to exfiltration at BULK_THRESHOLD = 5
repeats from one IP. That figure was tuned for AWS `GetObject`, where 5 reads is
already suspicious.

On Twilio, 5 messages is a normal application minute and 5,000 is an SMS-pumping
attack. Applying the AWS threshold unchanged would mark every healthy Twilio
integration as critical. TWILIO_BULK_THRESHOLD below is the per-platform value
rules.py should use once S3-Y7 makes the threshold platform-aware.

Severity rationale
------------------
Twilio abuse is metered: harm scales with volume, not with any single call. A
lone message is near-harmless (severity 2); thousands constitute both financial
abuse and reputational damage, since the victim's number gets blocked by
carriers. Number purchases sit at 3 because they carry a recurring monthly
charge and are the setup step for larger campaigns.
"""

VALID_CATEGORIES: set[str] = {
    "reconnaissance",
    "data_access",
    "exfiltration",
    "resource_abuse",
    "financial_abuse",
    "communication_abuse",
    "privilege_escalation",
}

VALID_SEVERITIES: set[int] = {1, 2, 3, 4}

# Messages from one source within the window before it counts as a campaign
# rather than normal application traffic. Deliberately far above the AWS value.
TWILIO_BULK_THRESHOLD = 20


TWILIO_API_TAXONOMY: dict[str, dict] = {
    # ================= PRIVILEGE ESCALATION (4) =================
    "api_key.created": {"category": "privilege_escalation", "severity": 4, "label": "API Key Created"},
    "api_key.deleted": {"category": "resource_abuse", "severity": 3, "label": "API Key Deleted"},
    "api_key.updated": {"category": "resource_abuse", "severity": 3, "label": "API Key Updated"},
    "subaccount.created": {"category": "privilege_escalation", "severity": 4, "label": "Subaccount Created"},
    "account.updated": {"category": "privilege_escalation", "severity": 4, "label": "Account Settings Changed"},

    # ================= COMMUNICATION ABUSE (2-4) =================
    # Outbound messaging — spam, smishing, and SMS pumping.
    "message.sent": {"category": "communication_abuse", "severity": 2, "label": "Message Sent"},
    "message.queued": {"category": "communication_abuse", "severity": 2, "label": "Message Queued"},
    "message.delivered": {"category": "communication_abuse", "severity": 2, "label": "Message Delivered"},
    # A failed send still costs money and still signals a campaign in progress.
    "message.failed": {"category": "communication_abuse", "severity": 2, "label": "Message Failed"},
    "message.undelivered": {"category": "communication_abuse", "severity": 2, "label": "Message Undelivered"},
    # Remaining Message statuses the collector can emit (`message.<status>`).
    "message.accepted": {"category": "communication_abuse", "severity": 2, "label": "Message Accepted"},
    "message.scheduled": {"category": "communication_abuse", "severity": 2, "label": "Message Scheduled"},
    "message.sending": {"category": "communication_abuse", "severity": 2, "label": "Message Sending"},
    # Twilio's WhatsApp `read` delivery status. The collector renames it so it
    # cannot collide with `message.read` below, which means a body was READ.
    "message.read_by_recipient": {"category": "communication_abuse", "severity": 2, "label": "Message Read By Recipient"},
    "message.partially_delivered": {"category": "communication_abuse", "severity": 2, "label": "Message Partially Delivered"},
    "message.canceled": {"category": "communication_abuse", "severity": 2, "label": "Message Canceled"},

    # Voice — premium-rate fraud is the expensive variant.
    "call.created": {"category": "communication_abuse", "severity": 3, "label": "Call Placed"},
    "call.completed": {"category": "communication_abuse", "severity": 3, "label": "Call Completed"},
    "call.initiated": {"category": "communication_abuse", "severity": 3, "label": "Call Initiated"},
    # Remaining Call statuses the collector can emit (`call.<status>`). A call
    # that never connected is still an attempt, but carries little cost.
    "call.queued": {"category": "communication_abuse", "severity": 3, "label": "Call Queued"},
    "call.ringing": {"category": "communication_abuse", "severity": 3, "label": "Call Ringing"},
    "call.in-progress": {"category": "communication_abuse", "severity": 3, "label": "Call In Progress"},
    "call.busy": {"category": "communication_abuse", "severity": 2, "label": "Call Attempt (Busy)"},
    "call.no-answer": {"category": "communication_abuse", "severity": 2, "label": "Call Attempt (No Answer)"},
    "call.canceled": {"category": "communication_abuse", "severity": 2, "label": "Call Canceled"},
    "call.failed": {"category": "communication_abuse", "severity": 2, "label": "Call Failed"},

    # Verification abuse — burning the victim's verification quota.
    "verification.sent": {"category": "communication_abuse", "severity": 3, "label": "Verification Sent"},
    "verification_check.created": {"category": "communication_abuse", "severity": 2, "label": "Verification Checked"},

    # ================= FINANCIAL ABUSE (3) =================
    "number.purchased": {"category": "financial_abuse", "severity": 3, "label": "Phone Number Purchased"},
    "number.released": {"category": "resource_abuse", "severity": 2, "label": "Phone Number Released"},
    "short_code.created": {"category": "financial_abuse", "severity": 3, "label": "Short Code Created"},
    "messaging_service.created": {"category": "financial_abuse", "severity": 3, "label": "Messaging Service Created"},

    # ================= DATA ACCESS (2-3) =================
    # Message bodies contain one-time passcodes and personal data, so reading
    # message history is a genuine data breach, not mere reconnaissance.
    "message.read": {"category": "data_access", "severity": 3, "label": "Message Body Read"},
    "message.media.read": {"category": "data_access", "severity": 3, "label": "Message Media Read"},
    "recording.read": {"category": "data_access", "severity": 3, "label": "Call Recording Accessed"},
    "transcription.read": {"category": "data_access", "severity": 3, "label": "Transcription Accessed"},
    "call.read": {"category": "data_access", "severity": 2, "label": "Call Record Read"},

    # ================= RESOURCE ABUSE (3) =================
    "application.created": {"category": "resource_abuse", "severity": 3, "label": "TwiML App Created"},
    "application.updated": {"category": "resource_abuse", "severity": 3, "label": "TwiML App Updated"},
    "webhook.updated": {"category": "resource_abuse", "severity": 3, "label": "Webhook Redirected"},

    # ================= RECONNAISSANCE (1) =================
    "account.fetched": {"category": "reconnaissance", "severity": 1, "label": "Account Fetched"},
    "balance.fetched": {"category": "reconnaissance", "severity": 1, "label": "Balance Checked"},
    "message.list": {"category": "reconnaissance", "severity": 1, "label": "List Messages"},
    "call.list": {"category": "reconnaissance", "severity": 1, "label": "List Calls"},
    "number.list": {"category": "reconnaissance", "severity": 1, "label": "List Phone Numbers"},
    "usage.fetched": {"category": "reconnaissance", "severity": 1, "label": "Usage Records Fetched"},
}
