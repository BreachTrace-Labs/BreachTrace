"""
BreachTrace Demo Trigger
------------------------
Run this script while the backend is running on port 8000 to inject a
simulated credential-leak incident and watch it flow through the full pipeline.

Usage:
    python demo_trigger.py
"""
import json
import requests
from datetime import datetime, timezone, timedelta

# ── Credentials from .env ──────────────────────────────────────────────────────
KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "testExpSecretKey"
# ──────────────────────────────────────────────────────────────────────────────

# exposure_start 25 minutes ago so any real CloudTrail events fall inside the window
exposure_start = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()

# The diff must contain the KEY_ID in a format the scanner recognises
diff_text = (
    f"+  # WARNING: do not commit credentials\n"
    f"+  AWS_ACCESS_KEY_ID={KEY_ID}\n"
    f"+  AWS_SECRET_ACCESS_KEY={SECRET_KEY}\n"
    f"+  AWS_REGION=ap-south-1\n"
)

print("Sending simulate request...")
resp = requests.post(
    "http://localhost:8000/test/simulate",
    json={
        "repo_url": "https://github.com/group03/breachtrace-demo",
        "diff_text": diff_text,
        "access_key_id": KEY_ID,
        "secret_access_key": SECRET_KEY,
        "exposure_start": exposure_start,
    },
    timeout=15,
)

if resp.status_code != 202:
    print(f"ERROR {resp.status_code}:")
    print(resp.text)
    raise SystemExit(1)

data = resp.json()
print(json.dumps(data, indent=2))

incident_id = data["incidents"][0]["incident_id"]
print()
print("=" * 60)
print(f"Incident ID : {incident_id}")
print(f"Dashboard   : http://localhost:5173")
print(f"Detail page : http://localhost:5173/incident/{incident_id}")
print("=" * 60)
print("Pipeline is running in the background.")
print("Refresh the dashboard — the incident should appear within 2 seconds.")
