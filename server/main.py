from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings

settings = get_settings()

app = FastAPI(
    title="BreachTrace",
    description="Universal Credential Forensics API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "environment": settings.ENVIRONMENT,
    }


# ── Incidents ─────────────────────────────────────────────────────────────────

@app.get("/incidents")
async def list_incidents():
    """List all incidents (newest first)."""
    # TODO: wire to DB query
    return []


@app.get("/incidents/stats")
async def incident_stats():
    """Aggregate statistics across all incidents."""
    # TODO: implement
    return {
        "total": 0,
        "by_severity": {},
        "avg_detection_time_s": 0,
        "avg_report_time_s": 0,
        "top_categories": [],
    }


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Full incident record with nested events."""
    # TODO: wire to DB query
    return {"detail": "Not found"}


@app.get("/incidents/{incident_id}/timeline")
async def get_incident_timeline(incident_id: str):
    """Forensic events sorted by timestamp."""
    # TODO: wire to DB query
    return []


@app.post("/incidents/{incident_id}/collect")
async def trigger_collection(incident_id: str):
    """Manually re-trigger forensic collection."""
    # TODO: implement
    return {"status": "triggered"}


@app.post("/incidents/{incident_id}/classify")
async def trigger_classification(incident_id: str):
    """Manually re-run the classifier on existing events."""
    # TODO: implement
    return {"status": "triggered"}


@app.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str):
    """Partial update — report_text, remediation_steps, etc."""
    # TODO: implement
    return {"status": "updated"}


# ── Webhook ───────────────────────────────────────────────────────────────────

@app.post("/webhook/github")
async def github_webhook():
    """Receive GitHub push events, detect credentials, fire pipeline."""
    # TODO: implement (validate HMAC, parse payload, scan diff)
    return {"status": "received"}


# ── Test / Simulate ───────────────────────────────────────────────────────────

@app.post("/test/simulate")
async def simulate_incident():
    """
    Skip GitHub API — directly provide diff text for testing.
    Body: { repo_url, diff_text, access_key_id }
    """
    # TODO: implement
    return {"status": "simulated"}


# ── Research ──────────────────────────────────────────────────────────────────

@app.post("/research/record")
async def record_experiment():
    """Save experiment run result from the research harness."""
    # TODO: implement
    return {"status": "recorded"}


@app.get("/research/export")
async def export_experiments():
    """Export all experiment runs as JSON."""
    # TODO: wire to DB query
    return []
