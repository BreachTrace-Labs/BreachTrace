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

Message and Call resources carry a real per-item price, so financial impact for
Twilio is measured rather than estimated wherever Twilio has populated it.
Price is negative in Twilio's API (an amount charged); it is normalised to a
positive magnitude in raw_data.
"""
from __future__ import annotations

import logging
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

    # ------------------------------------------------------------------
    # Retryable list calls — the SDK paginates internally via `limit`
    # ------------------------------------------------------------------
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _list_messages(self, start_time: datetime, end_time: datetime) -> list[Any]:
        return list(
            self._client.messages.list(
                date_sent_after=start_time,
                date_sent_before=end_time,
                limit=_MAX_PER_RESOURCE,
            )
        )

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _list_calls(self, start_time: datetime, end_time: datetime) -> list[Any]:
        return list(
            self._client.calls.list(
                start_time_after=start_time,
                start_time_before=end_time,
                limit=_MAX_PER_RESOURCE,
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

        Returns message and call activity in the window, sorted chronologically.
        Reads are not represented — see the module docstring.
        """
        logger.info(
            "[TWILIO] Querying messages and calls %s -> %s",
            start_time.isoformat(),
            end_time.isoformat(),
        )

        events: list[ForensicEvent] = []
        events.extend(self._map_message(m) for m in self._list_messages(start_time, end_time))
        events.extend(self._map_call(c) for c in self._list_calls(start_time, end_time))
        events.sort(key=lambda e: e.timestamp)

        logger.info("[TWILIO] Collected %d forensic events", len(events))
        return events

    def _map_message(self, message: Any) -> ForensicEvent:
        status = getattr(message, "status", None) or "sent"
        price = _abs_price(getattr(message, "price", None))

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="twilio",
            timestamp=_as_utc(getattr(message, "date_sent", None)),
            # Matches the taxonomy_twilio keys: message.sent / message.failed / …
            api_action=f"message.{status}",
            event_source="api.twilio.com",
            source_ip=None,
            user_agent=None,
            # The destination number IS the affected resource for spam abuse.
            affected_resource=getattr(message, "to", None),
            resource_type="message",
            principal_id=getattr(message, "account_sid", None),
            success=status not in ("failed", "undelivered"),
            error_code=str(getattr(message, "error_code", "") or "") or None,
            raw_data={
                "sid": getattr(message, "sid", None),
                "from": getattr(message, "from_", None),
                "to": getattr(message, "to", None),
                "status": status,
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

        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="twilio",
            timestamp=_as_utc(getattr(call, "start_time", None)),
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
