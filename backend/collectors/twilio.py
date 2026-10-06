"""
Twilio collector.

Reconstructs what a leaked Twilio credential did during the exposure window by
reading the Messages and Calls resources.

Required package:
    twilio>=8.0.0

--------------------------------------------------------------------------
WHAT THIS CAN AND CANNOT SEE
--------------------------------------------------------------------------
Twilio exposes resource lists (messages sent, calls placed), not an audit log.
So:

  * Outbound abuse — SMS pumping, smishing, premium-rate call fraud — is fully
    visible, because each one creates a Message or Call resource.
  * Reads are invisible. An attacker who enumerated message bodies to harvest
    one-time passcodes leaves no trace here. Message bodies are a common source
    of OTPs and PII, so this is a real blind spot, not a minor one.
  * Twilio's Monitor/Events API covers account configuration changes and needs
    additional permissions; it is deliberately out of scope for this sprint.
  * Inbound messages and calls are skipped. They are created by whoever texted
    or dialled the account's numbers, not by anyone holding the credential, and
    counting them would file every healthy integration's inbound traffic as
    communication abuse.

Message and Call resources carry a real per-item price, so financial impact for
Twilio is measured rather than estimated wherever Twilio has populated it.
Price is negative in Twilio's API (an amount charged); it is normalised to a
positive magnitude in raw_data.

--------------------------------------------------------------------------
WHOSE ACCOUNT IS QUERIED?
--------------------------------------------------------------------------
The leaked Account SID, always. The configured TWILIO_ACCOUNT_SID /
TWILIO_AUTH_TOKEN only authenticate the request. Listing `client.messages`
would read the *configured* account instead, which silently reports another
account's traffic whenever the leaked SID is a subaccount or a different
account. Scoping to the leaked SID makes Twilio return its data (subaccounts
are readable with the parent's credentials) or fail loudly.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# Cap per resource type. An SMS-pumping run can produce enormous volume, and
# past a few thousand the severity verdict does not change.
_MAX_PER_RESOURCE = 5_000

# Twilio's documented PageSize maximum. Without it the SDK requests
# PageSize=_MAX_PER_RESOURCE in one call; the SDK follows next_page_uri instead.
_PAGE_SIZE = 1_000

_ACCOUNT_SID_PATTERN = re.compile(r"^AC[0-9a-f]{32}$")

# Twilio's WhatsApp `read` status would otherwise become `message.read`, which
# the taxonomy reserves for an attacker reading message bodies.
_MESSAGE_STATUS_ACTIONS = {"read": "read_by_recipient"}


def _as_utc(moment: datetime | None) -> datetime:
    if moment is None:
        return datetime.now(tz=timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _abs_price(value: Any) -> float | None:
    """Twilio prices are negative (amount charged); report the magnitude."""
    try:
        return abs(float(value))
    except (TypeError, ValueError):
        return None


def _is_inbound(resource: Any) -> bool:
    return (getattr(resource, "direction", None) or "").lower() == "inbound"


class TwilioUsageCollector(BaseCollector):
    """Queries Twilio Messages and Calls for activity during the window."""

    platform = "twilio"

    def __init__(self, account_sid: str | None = None, auth_token: str | None = None) -> None:
        from twilio.rest import Client  # lazy import; SDK optional for AWS-only installs

        import config

        sid = account_sid or getattr(config, "TWILIO_ACCOUNT_SID", "")
        token = auth_token or getattr(config, "TWILIO_AUTH_TOKEN", "")
        if not sid or not token:
            raise ValueError(
                "Twilio credentials missing: set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN"
            )
        self._client = Client(sid, token)

    def _account(self, account_sid: str) -> Any:
        """Account context for the leaked SID; the client's own account otherwise."""
        if _ACCOUNT_SID_PATTERN.match(account_sid or ""):
            return self._client.api.v2010.accounts(account_sid)
        logger.warning(
            "[TWILIO] %r is not an Account SID; querying the configured account", account_sid
        )
        return self._client.api.v2010.account

    # ------------------------------------------------------------------
    # Retryable list calls — the SDK paginates internally via `limit`
    # ------------------------------------------------------------------
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _list_messages(self, account: Any, start_time: datetime, end_time: datetime) -> list[Any]:
        return list(
            account.messages.list(
                date_sent_after=start_time,
                date_sent_before=end_time,
                limit=_MAX_PER_RESOURCE,
                page_size=_PAGE_SIZE,
            )
        )

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _list_calls(self, account: Any, start_time: datetime, end_time: datetime) -> list[Any]:
        return list(
            account.calls.list(
                start_time_after=start_time,
                start_time_before=end_time,
                limit=_MAX_PER_RESOURCE,
                page_size=_PAGE_SIZE,
            )
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        credential = the leaked Twilio Account SID (AC…).

        Returns outbound message and call activity in the window, sorted
        chronologically. Reads are not represented — see the module docstring.
        """
        logger.info(
            "[TWILIO] Querying messages and calls %s -> %s",
            start_time.isoformat(),
            end_time.isoformat(),
        )

        account = self._account(credential)
        messages = self._list_messages(account, start_time, end_time)
        calls = self._list_calls(account, start_time, end_time)

        events: list[ForensicEvent] = []
        events.extend(self._map_message(m) for m in messages if not _is_inbound(m))
        events.extend(self._map_call(c) for c in calls if not _is_inbound(c))
        events.sort(key=lambda e: e.timestamp)

        skipped = len(messages) + len(calls) - len(events)
        logger.info(
            "[TWILIO] Collected %d forensic events (%d inbound skipped)", len(events), skipped
        )
        return events

    def _map_message(self, message: Any) -> ForensicEvent:
        status = getattr(message, "status", None) or "sent"
        price = _abs_price(getattr(message, "price", None))
        # date_sent is unset until Twilio hands the message to a carrier.
        sent_at = getattr(message, "date_sent", None) or getattr(message, "date_created", None)

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="twilio",
            timestamp=_as_utc(sent_at),
            # Matches the taxonomy_twilio keys: message.sent / message.failed / …
            api_action=f"message.{_MESSAGE_STATUS_ACTIONS.get(status, status)}",
            event_source="api.twilio.com",
            source_ip=None,
            user_agent=None,
            # The destination number IS the affected resource for spam abuse.
            affected_resource=getattr(message, "to", None),
            resource_type="message",
            principal_id=getattr(message, "account_sid", None),
            success=status not in ("failed", "undelivered", "canceled"),
            error_code=str(getattr(message, "error_code", "") or "") or None,
            raw_data={
                "sid": getattr(message, "sid", None),
                "from": getattr(message, "from_", None),
                "to": getattr(message, "to", None),
                "status": status,
                "direction": getattr(message, "direction", None),
                "price": price,
                "price_unit": getattr(message, "price_unit", None),
                "num_segments": getattr(message, "num_segments", None),
                # Message bodies routinely contain one-time passcodes and personal
                # data. Storing them would move that content into our database and
                # into Gemini prompts, so only the length is recorded.
                "body_length": len(getattr(message, "body", "") or ""),
            },
        )

    def _map_call(self, call: Any) -> ForensicEvent:
        status = getattr(call, "status", None) or "completed"
        price = _abs_price(getattr(call, "price", None))
        started_at = getattr(call, "start_time", None) or getattr(call, "date_created", None)

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="twilio",
            timestamp=_as_utc(started_at),
            api_action=f"call.{status}",
            event_source="api.twilio.com",
            source_ip=None,
            user_agent=None,
            affected_resource=getattr(call, "to", None),
            resource_type="call",
            principal_id=getattr(call, "account_sid", None),
            success=status not in ("failed", "busy", "no-answer", "canceled"),
            error_code=None,
            raw_data={
                "sid": getattr(call, "sid", None),
                "from": getattr(call, "from_", None),
                "to": getattr(call, "to", None),
                "status": status,
                "duration": getattr(call, "duration", None),
                "price": price,
                "price_unit": getattr(call, "price_unit", None),
                "direction": getattr(call, "direction", None),
            },
        )
