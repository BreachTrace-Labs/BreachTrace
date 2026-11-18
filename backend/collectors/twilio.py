"""Read account-scoped Twilio activity without collecting message content.

Messages and calls are account activity, not per-key attribution. Monitor Events
cover supported administrative operations, subject to permissions and retention.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)
_MAX_PER_RESOURCE = 5_000
_PAGE_SIZE = 1_000
_ACCOUNT_SID_PATTERN = re.compile(r"^AC[0-9a-fA-F]{32}$")
_KEY_SID_PATTERN = re.compile(r"^SK[0-9a-fA-F]{32}$")
_MESSAGE_STATUS_ACTIONS = {"read": "read_by_recipient"}
_MONITOR_ACTIONS = {
    "account-api-keys.created": "api_key.created",
    "account-api-keys.deleted": "api_key.deleted",
    "account-api-keys.updated": "api_key.updated",
    "account-keys.created": "api_key.created",
    "account-keys.deleted": "api_key.deleted",
    "account-keys.updated": "api_key.updated",
    "incoming-phone-number.updated": "webhook.updated",
    "incoming-phone-numbers.updated": "webhook.updated",
}


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _abs_price(value: Any) -> float | None:
    try:
        return abs(float(value))
    except (TypeError, ValueError):
        return None


def _is_outbound(resource: Any) -> bool:
    return str(getattr(resource, "direction", "") or "").lower().startswith("outbound")


def _timestamp(resource: Any, *fields: str) -> datetime | None:
    for field in fields:
        value = getattr(resource, field, None)
        if isinstance(value, datetime):
            return _as_utc(value)
    return None


class TwilioUsageCollector(BaseCollector):
    """Collect bounded Messages, Calls and Monitor Events for one account."""
    platform = "twilio"

    def __init__(self, account_sid: str | None = None, auth_token: str | None = None, *, reader: dict | None = None) -> None:
        from twilio.rest import Client
        import config

        self.account_sid = reader['account_sid'] if reader is not None else (account_sid or getattr(config, "TWILIO_ACCOUNT_SID", ""))
        token = reader.get('auth_token', '') if reader is not None else (auth_token if auth_token is not None else getattr(config, "TWILIO_AUTH_TOKEN", ""))
        key_sid = reader.get('api_key_sid', '') if reader is not None else (getattr(config, "TWILIO_API_KEY_SID", "") if auth_token is None else "")
        key_secret = reader.get('api_key_secret', '') if reader is not None else (getattr(config, "TWILIO_API_KEY_SECRET", "") if auth_token is None else "")
        if not _ACCOUNT_SID_PATTERN.fullmatch(self.account_sid):
            raise ValueError("Twilio collection requires the owning Account SID (AC followed by 32 hex characters)")
        if key_sid or key_secret:
            if not _KEY_SID_PATTERN.fullmatch(key_sid) or not key_secret:
                raise ValueError("Set both TWILIO_API_KEY_SID and TWILIO_API_KEY_SECRET")
            self._client = Client(key_sid, key_secret, self.account_sid)
        elif token:
            self._client = Client(self.account_sid, token)
        else:
            raise ValueError("Twilio reader credentials missing: configure an API key or Auth Token")

    def _account(self, account_sid: str) -> Any:
        if not _ACCOUNT_SID_PATTERN.fullmatch(account_sid or "") or account_sid.lower() != self.account_sid.lower():
            raise ValueError("Twilio reader is scoped to a different account; configure the owning Account SID")
        return self._client.api.v2010.accounts(self.account_sid)

    @staticmethod
    def _bounded(items: list[Any], resource: str) -> list[Any]:
        if len(items) > _MAX_PER_RESOURCE:
            raise ValueError(f"Twilio {resource} exceeds the collection limit; narrow the account or window")
        return items

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    def _list_messages(self, account: Any, start_time: datetime, end_time: datetime) -> list[Any]:
        # DateSent filters omit queued messages with no date_sent. Fetch bounded
        # account history and apply the exact window locally using creation time.
        return self._bounded(list(account.messages.list(limit=_MAX_PER_RESOURCE + 1, page_size=_PAGE_SIZE)), "messages")

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    def _list_calls(self, account: Any, start_time: datetime, end_time: datetime) -> list[Any]:
        return self._bounded(list(account.calls.list(limit=_MAX_PER_RESOURCE + 1, page_size=_PAGE_SIZE)), "calls")

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    def _list_monitor(self, start_time: datetime, end_time: datetime) -> list[Any]:
        return self._bounded(list(self._client.monitor.v1.events.list(
            start_date=start_time, end_date=end_time, limit=_MAX_PER_RESOURCE + 1, page_size=_PAGE_SIZE,
        )), "monitor events")

    def collect(self, credential: str, start_time: datetime, end_time: datetime) -> list[ForensicEvent]:
        account = self._account(credential)
        start_time, end_time = _as_utc(start_time), _as_utc(end_time)
        if end_time < start_time:
            raise ValueError("Twilio collection window ends before it starts")
        messages = self._list_messages(account, start_time, end_time)
        calls = self._list_calls(account, start_time, end_time)
        monitor = self._list_monitor(start_time, end_time)
        events = []
        for resource, fields, mapper in (
            *((m, ("date_sent", "date_created"), self._map_message) for m in messages if _is_outbound(m)),
            *((c, ("start_time", "date_created"), self._map_call) for c in calls if _is_outbound(c)),
            *((e, ("event_date",), self._map_monitor) for e in monitor),
        ):
            moment = _timestamp(resource, *fields)
            if moment is None:
                raise ValueError("Twilio returned a resource without a usable timestamp")
            if start_time <= moment <= end_time:
                if mapper == self._map_monitor:
                    event_account = getattr(resource, "account_sid", None)
                    if event_account and str(event_account).lower() != self.account_sid.lower():
                        raise ValueError("Twilio Monitor returned an event from a different account")
                events.append(mapper(resource))
        events.sort(key=lambda e: e.timestamp)
        logger.info("[TWILIO] Collected %d account events", len(events))
        return events

    def _map_message(self, message: Any) -> ForensicEvent:
        status = str(getattr(message, "status", None) or "sent").lower()
        return ForensicEvent(
            platform="twilio", timestamp=_timestamp(message, "date_sent", "date_created"),
            api_action=f"message.{_MESSAGE_STATUS_ACTIONS.get(status, status)}", event_source="api.twilio.com",
            source_ip=None, affected_resource=getattr(message, "to", None), resource_type="message",
            principal_id=getattr(message, "account_sid", None), success=status not in ("failed", "undelivered", "canceled"),
            error_code=str(getattr(message, "error_code", "") or "") or None,
            raw_data={"sid": getattr(message, "sid", None), "from": getattr(message, "from_", None),
                      "to": getattr(message, "to", None), "status": status, "direction": getattr(message, "direction", None),
                      "price": _abs_price(getattr(message, "price", None)), "price_unit": getattr(message, "price_unit", None),
                      "num_segments": getattr(message, "num_segments", None)},
        )

    def _map_call(self, call: Any) -> ForensicEvent:
        status = str(getattr(call, "status", None) or "completed").lower()
        return ForensicEvent(
            platform="twilio", timestamp=_timestamp(call, "start_time", "date_created"),
            api_action=f"call.{status}", event_source="api.twilio.com", source_ip=None,
            affected_resource=getattr(call, "to", None), resource_type="call", principal_id=getattr(call, "account_sid", None),
            success=status not in ("failed", "busy", "no-answer", "canceled"),
            raw_data={"sid": getattr(call, "sid", None), "from": getattr(call, "from_", None),
                      "to": getattr(call, "to", None), "status": status, "duration": getattr(call, "duration", None),
                      "price": _abs_price(getattr(call, "price", None)), "price_unit": getattr(call, "price_unit", None),
                      "direction": getattr(call, "direction", None)},
        )

    def _map_monitor(self, event: Any) -> ForensicEvent:
        original = str(getattr(event, "event_type", "") or "")
        action = _MONITOR_ACTIONS.get(original, original)
        if original == "account.created" and getattr(event, "resource_sid", None) != self.account_sid:
            action = "subaccount.created"
        return ForensicEvent(
            platform="twilio", timestamp=_timestamp(event, "event_date"), api_action=action,
            event_source="monitor.twilio.com", source_ip=getattr(event, "source_ip_address", None),
            affected_resource=getattr(event, "resource_sid", None), resource_type=getattr(event, "resource_type", None),
            principal_id=getattr(event, "actor_sid", None),
            raw_data={"sid": getattr(event, "sid", None), "event_type": original,
                      "actor_type": getattr(event, "actor_type", None), "source": getattr(event, "source", None)},
        )
