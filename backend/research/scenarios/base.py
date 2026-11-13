"""
Scenario framework for *real* incidents (see real_incident_plan.pdf).

A scenario does four things against a real account:

  1. act      - make the attacker's real API calls with the experiment identity
  2. leak     - POST the credential to /test/simulate so detection -> window ->
                collection -> classification -> scoring -> report run for real
  3. assert   - wait for status=complete, diff collected events vs `expected`
  4. cleanup  - always runs (finally); then revoke the leaked key

Order note: the plan lists "leak" first, but BreachTrace collects once, right
after /test/simulate, and cloud audit logs lag (Azure Activity Log: 2-15 min).
So `run()` acts first, polls until the audit log shows the calls, then leaks.
The pipeline looks back 120 min before exposure_start, so the events are inside
the window. Cleanup runs *after* collection so deletes don't pollute the trail.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Expect:
    api_action: str
    category: str
    min_severity: int
    optional: bool = False  # reported if absent, but does not fail the scenario


@dataclass
class Diff:
    missing: list[str] = field(default_factory=list)
    misclassified: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    optional_missing: list[str] = field(default_factory=list)
    matched: int = 0

    def ok(self, blind: bool) -> bool:
        # `unexpected` is informational: an attacker trail legitimately contains
        # scaffolding calls (resource-group create etc.).
        return not self.misclassified and (blind or not self.missing)


def diff_events(expected: list[Expect], events: list[dict]) -> Diff:
    """Compare collected incident events with the scenario's expectations."""
    d = Diff()
    by_action: dict[str, list[dict]] = {}
    for e in events:
        by_action.setdefault(e.get("api_action", ""), []).append(e)

    for exp in expected:
        hits = by_action.get(exp.api_action)
        if not hits:
            (d.optional_missing if exp.optional else d.missing).append(exp.api_action)
            continue
        good = [
            h for h in hits
            if h.get("impact_category") == exp.category
            and (h.get("severity_weight") or 0) >= exp.min_severity
        ]
        if good:
            d.matched += 1
        else:
            h = hits[0]
            d.misclassified.append(
                f"{exp.api_action}: got {h.get('impact_category')}/sev{h.get('severity_weight')}, "
                f"expected {exp.category}/sev>={exp.min_severity}"
            )

    known = {x.api_action for x in expected}
    d.unexpected = sorted(a for a in by_action if a and a not in known)
    return d


class Scenario:
    """Subclass per incident. Set the class attributes and implement act()."""

    id: str = ""
    platform: str = ""
    impact_class: str = ""
    description: str = ""
    mode: str = "live"            # live | denied-but-logged | live+denied-but-logged
    expected_blind: bool = False  # class is invisible in this platform's audit log
    expected: list[Expect] = []
    min_wait_s: int = 0           # floor on audit-log wait (needed to confirm blindness)

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.api_calls: list[str] = []
        self.report: dict = {}

    # -- to implement ---------------------------------------------------------
    def acquire(self) -> None: ...
    def act(self) -> None: raise NotImplementedError
    def cleanup(self) -> None: ...
    def revoke(self) -> str: return "not revoked"
    def credential_id(self) -> str: raise NotImplementedError
    def leak_diff_text(self) -> str: raise NotImplementedError
    def audit_visible(self, since: datetime) -> bool: raise NotImplementedError

    # -- shared flow ----------------------------------------------------------
    def note(self, msg: str) -> None:
        LOG.info("[%s] %s", self.id, msg)
        self.notes.append(msg)

    def wait_for_audit_log(self, since: datetime, timeout_s: int = 1500, poll_s: int = 45) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            try:
                if self.audit_visible(since) and time.time() - t0 >= self.min_wait_s:
                    return True
            except Exception as exc:  # DNS blips / timeouts must not abort a long wait
                self.note(f"audit-log poll failed, retrying: {type(exc).__name__}")
            time.sleep(poll_s)
        return False

    def leak(self, api_base: str, exposure_start: datetime) -> str:
        resp = requests.post(
            f"{api_base}/test/simulate",
            json={
                "platform": self.platform,
                "diff_text": self.leak_diff_text(),
                "credential": self.credential_id(),
                "exposure_start": exposure_start.isoformat(),
            },
            timeout=30,
        )
        resp.raise_for_status()
        incident_id = resp.json().get("incident_id")
        if not incident_id:
            raise RuntimeError(f"simulate created no incident: {resp.text[:300]}")
        return incident_id

    def wait_complete(self, api_base: str, incident_id: str, timeout_s: int = 600) -> dict:
        t0 = time.time()
        incident: dict = {}
        while time.time() - t0 < timeout_s:
            incident = requests.get(f"{api_base}/incidents/{incident_id}", timeout=15).json()
            if incident.get("status") in ("complete", "error"):
                break
            time.sleep(5)
        return incident

    def run(self, api_base: str = "http://localhost:8000", record: bool = True):
        from research.harness import ScenarioResult, record_run

        result = ScenarioResult(name=self.id, started_at=datetime.now(timezone.utc))
        t0 = time.time()
        incident: dict = {}
        diff = Diff()
        try:
            self.acquire()
            act_start = datetime.now(timezone.utc)
            try:
                self.act()
            except Exception as exc:  # keep going: partial trails are still evidence
                result.success = False
                self.note(f"act() failed: {exc}")

            self.note("waiting for the audit log to show the calls (can take 2-15 min)")
            visible = self.wait_for_audit_log(act_start)
            if not visible:
                self.note("audit log never showed the expected calls within the timeout")

            exposure_start = datetime.now(timezone.utc)
            incident_id = self.leak(api_base, exposure_start)
            t_leak = time.time()
            incident = self.wait_complete(api_base, incident_id)
            events = incident.get("events", [])
            diff = diff_events(self.expected, events)

            observed_blind = self.expected_blind and not events
            self.report = {
                "incident_id": incident_id,
                "status": incident.get("status"),
                "events": len(events),
                "matched": diff.matched,
                "missing": diff.missing,
                "misclassified": diff.misclassified,
                "unexpected": diff.unexpected,
                "optional_missing": diff.optional_missing,
                "expected_blind": self.expected_blind,
                "blind_confirmed": observed_blind,
            }
            if incident.get("status") != "complete":
                result.success = False
                self.note(f"incident ended in status={incident.get('status')}")
            if not diff.ok(self.expected_blind):
                result.success = False

            exp = {
                "run_number": 1,
                "platform": self.platform,
                "incident_id": incident_id,
                "api_calls_made": sorted({e.get("api_action") for e in events if e.get("api_action")}),
                "impact_categories": sorted({e.get("impact_category") for e in events if e.get("impact_category")}),
                "overall_severity": incident.get("overall_severity"),
                "detection_time_s": round(t_leak - t0, 1),
                "report_time_s": round(time.time() - t0, 1),
                "notes": f"scenario={self.id} class={self.impact_class} mode={self.mode} "
                         f"blind={self.expected_blind} events={len(events)} ok={result.success}",
            }
            if record:
                record_run(exp, api_base)
        finally:
            try:
                self.cleanup()
            except Exception as exc:
                result.success = False
                self.note(f"CLEANUP FAILED - check the account manually: {exc}")
            self.note(f"revocation: {self.revoke()}")
            result.api_calls = list(self.api_calls)
            result.notes = list(self.notes)
            result.complete()
        return result
