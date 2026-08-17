"""
Stripe Events API collector.

Reconstructs what a leaked Stripe secret key did during the exposure window by
reading the account's event log.

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
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from tenacity import retry, stop_after_attempt, wait_exponential

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent

logger = logging.getLogger(__name__)

# Stripe caps `limit` at 100 per page.
_PAGE_SIZE = 100

# Stop paging runaway accounts. A leaked key producing >10k events in one window
# is already a maximal-severity finding; more pages add cost, not information.
_MAX_EVENTS = 10_000


def _to_unix(moment: datetime) -> int:
    """Stripe filters on Unix seconds. Naive datetimes are assumed UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


class StripeEventsCollector(BaseCollector):
    """Queries the Stripe Events API for account activity during the window."""

    platform = "stripe"

    def __init__(self, api_key: str | None = None) -> None:
        import stripe  # imported lazily so the SDK is optional for AWS-only installs

        import config

        self._stripe = stripe
        # The leaked key itself is the natural credential to query with, but it
        # may already be revoked by the time the pipeline runs. Fall back to the
        # configured account key so collection still works post-revocation.
        self._api_key = api_key or getattr(config, "STRIPE_API_KEY", "")
        if not self._api_key:
            raise ValueError(
                "No Stripe API key available: set STRIPE_API_KEY or pass one explicitly"
            )

    # ------------------------------------------------------------------
    # Retryable page fetch
    # ------------------------------------------------------------------
    @retry(
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

            for event in data:
                yield event
                seen += 1
                if seen >= _MAX_EVENTS:
                    logger.warning(
                        "[STRIPE] Hit the %d-event cap; results truncated", _MAX_EVENTS
                    )
                    return

            if not getattr(page, "has_more", False):
                return
            starting_after = getattr(data[-1], "id", None)
            if not starting_after:
                return

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
        events = [self._map_event(e) for e in self._iter_events(start_time, end_time)]
        logger.info("[STRIPE] Collected %d forensic events", len(events))
        return events

    def _map_event(self, event: Any) -> ForensicEvent:
        """Map one Stripe event onto the shared ForensicEvent schema."""
        raw = event.to_dict() if hasattr(event, "to_dict") else dict(event)

        data_object = (raw.get("data") or {}).get("object") or {}
        request = raw.get("request") or {}
        if isinstance(request, str):  # older API versions return a bare request id
            request = {"id": request}

        created = raw.get("created")
        timestamp = (
            datetime.fromtimestamp(created, tz=timezone.utc)
            if isinstance(created, (int, float))
            else datetime.now(tz=timezone.utc)
        )

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
            principal_id=request.get("idempotency_key") or request.get("id"),
            success=True,  # Stripe only emits events for actions that happened
            error_code=None,
            raw_data=raw,
        )
