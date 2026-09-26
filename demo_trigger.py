"""
BreachTrace Demo Trigger
------------------------
Run this script while the backend is running on port 8000 to inject
simulated credential-leak incidents and watch them flow through the full
pipeline.

Usage:
    python demo_trigger.py                   # fires all five platforms
    python demo_trigger.py aws               # AWS only
    python demo_trigger.py gcp               # GCP only
    python demo_trigger.py azure             # Azure only
    python demo_trigger.py stripe            # Stripe only
    python demo_trigger.py twilio            # Twilio only

Stripe and Twilio actually query their live APIs during collection, so the
collector needs real (test-mode/trial) credentials in .env — STRIPE_API_KEY,
TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN — even though the *leaked* key below is
a synthetic placeholder used only to trip the detector. Without those set,
the incident is still created and shows up on the dashboard, but its pipeline
stage ends in 'error' instead of 'complete'.
"""
import json
import sys
import requests
from datetime import datetime, timezone, timedelta

BASE_URL = "http://localhost:8000"
exposure_start = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()


# ── AWS ────────────────────────────────────────────────────────────────────────
AWS_KEY_ID     = "AKIAUDOTYKQPCWNJ4GXV"
AWS_SECRET_KEY = "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"

AWS_DIFF = (
    f"+  # WARNING: do not commit credentials\n"
    f"+  AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
    f"+  AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY}\n"
    f"+  AWS_REGION=ap-south-1\n"
)

# ── GCP ────────────────────────────────────────────────────────────────────────
# Replace these placeholders with values from your GCP project before running.
GCP_CLIENT_EMAIL  = "breachtrace-experiment@YOUR_PROJECT_ID.iam.gserviceaccount.com"
GCP_PRIVATE_KEY_ID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"  # 40-char hex

GCP_DIFF = (
    f'+  "type": "service_account",\n'
    f'+  "project_id": "YOUR_PROJECT_ID",\n'
    f'+  "private_key_id": "{GCP_PRIVATE_KEY_ID}",\n'
    f'+  "client_email": "{GCP_CLIENT_EMAIL}",\n'
    f'+  "auth_uri": "https://accounts.google.com/o/oauth2/auth",\n'
)

# ── Azure ──────────────────────────────────────────────────────────────────────
# Service Principal Object ID from Enterprise Applications (matches Activity Log caller field)
AZURE_CLIENT_ID     = "2892686f-f224-4bfc-b698-bb1d461397be"
AZURE_CLIENT_SECRET = "ecb7faec-3299-4c37-aaa9-8cc81db3912a"

AZURE_DIFF = (
    f'+  # Azure service principal credentials\n'
    f'+  AZURE_CLIENT_ID={AZURE_CLIENT_ID}\n'
    f'+  AZURE_CLIENT_SECRET={AZURE_CLIENT_SECRET}\n'
    f'+  AZURE_TENANT_ID=ffffffff-0000-1111-2222-333333333333\n'
)

# ── Stripe ─────────────────────────────────────────────────────────────────────
# Synthetic key: matches the sk_test_ pattern so the detector fires. Replace
# with a real Stripe test-mode secret key (dashboard → Developers → API keys)
# if you want the collector to return real Events API activity.
STRIPE_SECRET_KEY = "sk_test_51NcX9kLZ8mQoT4vJ2wRbYfDgHjKpQrStUvWxYz1234"

STRIPE_DIFF = (
    f"+  # Stripe API key — do not commit\n"
    f"+  STRIPE_SECRET_KEY={STRIPE_SECRET_KEY}\n"
)

# ── Twilio ─────────────────────────────────────────────────────────────────────
# Synthetic SID + token: match the AC + 32-hex pattern with nearby context
# keywords so the detector fires. Replace with your real trial Account SID +
# Auth Token (twilio.com/console) for the collector to return real activity.
TWILIO_ACCOUNT_SID = "ACa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
TWILIO_AUTH_TOKEN = "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"

TWILIO_DIFF = (
    f"+  # Twilio credentials — do not commit\n"
    f"+  TWILIO_ACCOUNT_SID={TWILIO_ACCOUNT_SID}\n"
    f"+  TWILIO_AUTH_TOKEN={TWILIO_AUTH_TOKEN}\n"
)


def trigger(platform: str, diff_text: str, extra: dict | None = None) -> dict:
    payload: dict = {
        "repo_url": "https://github.com/group03/breachtrace-demo",
        "diff_text": diff_text,
        "exposure_start": exposure_start,
    }
    if extra:
        payload.update(extra)

    print(f"\n{'='*60}")
    print(f"Sending {platform.upper()} simulate request...")
    resp = requests.post(f"{BASE_URL}/test/simulate", json=payload, timeout=15)

    if resp.status_code not in (200, 202):
        print(f"ERROR {resp.status_code}: {resp.text}")
        return {}

    data = resp.json()
    print(json.dumps(data, indent=2))

    incidents = data.get("incidents", [])
    if not incidents:
        print(f"  [!] No incident created for {platform.upper()} — check scanner/diff text.")
        return data

    inc = incidents[0]
    print(f"\n  Incident ID : {inc['incident_id']}")
    print(f"  Platform    : {inc.get('platform', platform)}")
    print(f"  Hint        : {inc.get('credential_hint', '—')}")
    print(f"  Dashboard   : http://localhost:5173")
    print(f"  Detail page : http://localhost:5173/incident/{inc['incident_id']}")
    return data


def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["aws", "gcp", "azure", "stripe", "twilio"]

    if "aws" in targets:
        trigger("aws", AWS_DIFF, {
            "access_key_id": AWS_KEY_ID,
            "secret_access_key": AWS_SECRET_KEY,
        })

    if "gcp" in targets:
        trigger("gcp", GCP_DIFF)

    if "azure" in targets:
        trigger("azure", AZURE_DIFF)

    if "stripe" in targets:
        trigger("stripe", STRIPE_DIFF)

    if "twilio" in targets:
        trigger("twilio", TWILIO_DIFF)

    print(f"\n{'='*60}")
    print("Pipeline is running in the background.")
    print("Refresh the dashboard — incidents should appear within 2 seconds.")


if __name__ == "__main__":
    main()
