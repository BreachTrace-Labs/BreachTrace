"""
BreachTrace Demo Trigger
------------------------
Run this script while the backend is running on port 8000 to inject
simulated credential-leak incidents and watch them flow through the full
pipeline.

Usage:
    python demo_trigger.py            # fires all three platforms
    python demo_trigger.py aws        # AWS only
    python demo_trigger.py gcp        # GCP only
    python demo_trigger.py azure      # Azure only
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
# Replace these placeholders with values from your Azure app registrations.
AZURE_CLIENT_ID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # experiment app client ID
AZURE_CLIENT_SECRET = "AzureExperimentSecret~ReplaceMe.12345"  # 34+ chars

AZURE_DIFF = (
    f'+  # Azure service principal credentials\n'
    f'+  AZURE_CLIENT_ID={AZURE_CLIENT_ID}\n'
    f'+  AZURE_CLIENT_SECRET={AZURE_CLIENT_SECRET}\n'
    f'+  AZURE_TENANT_ID=ffffffff-0000-1111-2222-333333333333\n'
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
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["aws", "gcp", "azure"]

    if "aws" in targets:
        trigger("aws", AWS_DIFF, {
            "access_key_id": AWS_KEY_ID,
            "secret_access_key": AWS_SECRET_KEY,
        })

    if "gcp" in targets:
        trigger("gcp", GCP_DIFF)

    if "azure" in targets:
        trigger("azure", AZURE_DIFF)

    print(f"\n{'='*60}")
    print("Pipeline is running in the background.")
    print("Refresh the dashboard — incidents should appear within 2 seconds.")


if __name__ == "__main__":
    main()
