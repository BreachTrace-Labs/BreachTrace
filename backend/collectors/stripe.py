"""
Stripe Events API collector.

Reads account events during the exposure window; events do not identify the
API key that caused them.

Required package:
    stripe>=7.0.0

--------------------------------------------------------------------------
FORENSIC LIMITATION — state this, do not paper over it
--------------------------------------------------------------------------
The Stripe Events API records **state changes only**. A `GET /v1/customers`
that dumps every customer record produces NO event. Read-only exfiltration
through the Stripe API is therefore invisible to this collector.

Consequences:
  * Stripe is Tier 1 for write activity (charges, payouts, refunds, account
    changes) and blind to read activity.
  * An empty result is NOT evidence the key went unused. `collect()` returns
    an empty list either way, so the report must never phrase that as "no
    unauthorised activity occurred".

This mirrors the Azure control-plane/data-plane split and belongs in paper §7,
"Forensic Observability as a Platform Property".

--------------------------------------------------------------------------
WHOSE EVENTS ARE THESE?
--------------------------------------------------------------------------
Stripe scopes /v1/events to the account the API key belongs to, not to the key
that caused each event. So this returns everything that happened on the account
during the window, including legitimate activity by the owner.

`event.request.id` is present when an event was caused by an API call, and is
absent for dashboard actions and Stripe-initiated events. That is the only
attribution signal available, so it is surfaced in raw_data rather than used to
filter — dropping events on it would hide real attacker activity whenever
Stripe omits the field.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# Stripe caps `limit` at 100 per page.
_PAGE_SIZE = 100

# Stop paging runaway accounts. A leaked key producing >10k events in one window
# is already a maximal-severity finding; more pages add cost, not information.
_MAX_EVENTS = 10_000

_SECRET_KEY_PATTERN = re.compile(r"^(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]+$")


def _to_unix(moment: datetime) -> int:
    """Stripe filters on Unix seconds. Naive datetimes are assumed UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def _is_usable_key(value: str | None) -> bool:
    """True for a full secret/restricted key; False for a masked hint or None."""
    return bool(value) and _SECRET_KEY_PATTERN.match(value) is not None


def _is_transient(exc: BaseException) -> bool:
    """
    Retry rate limits, timeouts and 5xx only. A revoked key or a bad request
    will fail identically every time, and retrying it would delay the fallback
    to STRIPE_API_KEY by the whole backoff schedule.
    """
    import stripe

    return not isinstance(
        exc,
        (stripe.AuthenticationError, stripe.PermissionError, stripe.InvalidRequestError),
    )


def _event_to_dict(event: Any) -> dict:
    """
    Plain-dict view of a Stripe event, nested objects included.

    `dict(event)` is shallow — `data.object` stays a StripeObject, which breaks
    both `.get()` chains and JSON serialisation into raw_data. Newer SDKs
    recurse in `to_dict()`; older ones only via `to_dict_recursive()`.
    """
    if isinstance(event, dict):
        return event
    try:
        return event.to_dict(recursive=True, for_json=True)
    except TypeError:
        # stripe < 8: to_dict() takes no arguments and is shallow.
        return event.to_dict_recursive()


class StripeEventsCollector(BaseCollector):
    """Queries the Stripe Events API for account activity during the window."""

    platform = "stripe"

    def __init__(self, api_key: str | None = None) -> None:
        import stripe  # imported lazily so the SDK is optional for AWS-only installs

        import config

        self._stripe = stripe
        # The leaked key itself is the natural credential to query with: it is
        # the only one guaranteed to read the account (and mode — live vs test)
        # it belongs to. It may already be revoked by the time the pipeline
        # runs. A configured key is used only for an explicit refresh.
        self._fallback_key = api_key or getattr(config, "STRIPE_API_KEY", "")
        self._api_key = self._fallback_key

    # ------------------------------------------------------------------
    # Retryable page fetch
    # ------------------------------------------------------------------
    @retry(
        retry=retry_if_exception(_is_transient),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _fetch_page(
        self,
        start_time: datetime,
        end_time: datetime,
        starting_after: str | None,
    ) -> Any:
        params: dict[str, Any] = {
            "limit": _PAGE_SIZE,
            "created": {"gte": _to_unix(start_time), "lte": _to_unix(end_time)},
            "api_key": self._api_key,
        }
        if starting_after:
            params["starting_after"] = starting_after
        return self._stripe.Event.list(**params)

    def _iter_events(self, start_time: datetime, end_time: datetime) -> Iterator[Any]:
        """Page through the window, oldest cursor first."""
        starting_after: str | None = None
        seen = 0

        while True:
            page = self._fetch_page(start_time, end_time, starting_after)
            data = list(getattr(page, "data", []) or [])
            if not data:
                return

            for index, event in enumerate(data):
                yield event
                seen += 1
                if seen >= _MAX_EVENTS and (index < len(data) - 1 or getattr(page, "has_more", False)):
                    raise ValueError("Stripe event limit exceeded; narrow the collection window")

            if not getattr(page, "has_more", False):
                return
            starting_after = getattr(data[-1], "id", None)
            if not starting_after:
                raise ValueError("Stripe pagination cursor missing; results incomplete")

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
        credential = the leaked Stripe secret key (sk_live_… / rk_live_…).

        Returns every account event in the window. See the module docstring:
        an empty list does not prove the key was unused.
        """
        logger.info(
            "[STRIPE] Querying events %s -> %s", start_time.isoformat(), end_time.isoformat()
        )
        key = credential if _is_usable_key(credential) else self._fallback_key
        if not _is_usable_key(key):
            raise ValueError(
                "No Stripe API key available: the leaked key is not usable and "
                "STRIPE_API_KEY is not set"
            )
        # A configured key may belong to an entirely different account or
        # mode. Never silently substitute it after an exposed key fails.
        if credential and not _is_usable_key(credential):
            mode = re.match(r"^(?:sk|rk)_(live|test)_", credential)
            if mode and f"_{mode.group(1)}_" not in key:
                raise ValueError("Configured Stripe key mode does not match the detected credential")
        self._api_key = key
        return [self._map_event(e) for e in self._iter_events(start_time, end_time)]

    def _map_event(self, event: Any) -> ForensicEvent:
        """Map one Stripe event onto the shared ForensicEvent schema."""
        raw = _event_to_dict(event)

        data_object = (raw.get("data") or {}).get("object") or {}
        request = raw.get("request") or {}
        if isinstance(request, str):  # older API versions return a bare request id
            request = {"id": request}

        created = raw.get("created")
        if not isinstance(created, (int, float)) or isinstance(created, bool):
            raise ValueError("Stripe event is missing its creation timestamp")
        timestamp = datetime.fromtimestamp(created, tz=timezone.utc)

        # Stripe event snapshots may contain customer data and client secrets.
        # Retain only evidence needed for the timeline and financial totals.
        fields = ("id", "object", "amount", "amount_received", "amount_captured",
                  "amount_refunded", "currency", "payment_intent", "charge", "status")
        safe_object = {k: data_object[k] for k in fields
                       if k in data_object and isinstance(data_object[k], (str, int, float, bool, type(None)))}
        safe_raw = {"id": raw.get("id"), "type": raw.get("type"), "created": created,
                    "livemode": raw.get("livemode"), "data": {"object": safe_object},
                    "request": {"id": request.get("id")}}

        # Stripe has no source IP on events; the closest attribution is the
        # request id. Leave source_ip None rather than inventing a value — the
        # timeline renders "unknown IP", which is honest.
        return ForensicEvent(
            event_id=str(uuid.uuid4()),
            platform="stripe",
            timestamp=timestamp,
            api_action=raw.get("type", "unknown"),
            event_source="api.stripe.com",
            source_ip=None,
            user_agent=None,
            affected_resource=data_object.get("id"),
            resource_type=data_object.get("object"),
            # The request id (req_…) is what Stripe's dashboard request log is
            # keyed by, so it is the useful attribution handle.
            principal_id=request.get("id"),
            success=not (str(raw.get("type", "")).endswith((".failed", ".payment_failed"))),
            error_code=None,
            raw_data=safe_raw,
        )
