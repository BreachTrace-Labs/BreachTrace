"""Stream Stripe CLI sandbox request logs to one BreachTrace incident."""
from __future__ import annotations

import argparse
import json
import os
import time
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env.testing.local", override=False)
except ImportError:
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("incident_id", nargs="?", type=uuid.UUID, default=os.getenv("STRIPE_INCIDENT_ID"))
    parser.add_argument("--backend-url", default=os.getenv("BREACHTRACE_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--confirm-sandbox", action="store_true", help="Confirm Stripe CLI is logged into this incident's sandbox")
    args = parser.parse_args()
    if args.incident_id is None:
        parser.error("Provide incident_id or set STRIPE_INCIDENT_ID")
    if not args.confirm_sandbox:
        parser.error("Confirm the CLI account matches this incident with --confirm-sandbox")
    stripe = shutil.which("stripe")
    if not stripe:
        print("Stripe CLI is not installed. Install it and run 'stripe login' first.", file=sys.stderr)
        return 1
    cli_api_key = os.getenv("STRIPE_CLI_API_KEY", "")
    if not cli_api_key.startswith("rk_test_"):
        print("Set STRIPE_CLI_API_KEY to a dedicated Stripe test restricted key in .env.testing.local.", file=sys.stderr)
        return 2
    if not os.getenv("STRIPE_LOG_INGEST_TOKEN"):
        print("Set STRIPE_LOG_INGEST_TOKEN in .env.testing.local and the backend environment.", file=sys.stderr)
        return 2
    endpoint = f"{args.backend_url.rstrip('/')}/incidents/{args.incident_id}/stripe-request-logs"
    env = dict(os.environ, NO_COLOR="1")
    # A dedicated request-log-capable key. Do not repurpose the exposed key
    # or the backend's separate Events API reader.
    env["STRIPE_API_KEY"] = cli_api_key
    print("Streaming sandbox request metadata to the incident. Press Ctrl+C to stop.", flush=True)
    proc = subprocess.Popen([stripe, "logs", "tail", "--format", "JSON"], stdout=subprocess.PIPE,
                            stderr=None, text=True, bufsize=1, env=env)
    buffer = ""
    decoder = json.JSONDecoder()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if not buffer:
                start = line.find("{")
                if start < 0:
                    continue
                line = line[start:]
            buffer += line
            if len(buffer) > 100_000:
                print("Skipped oversized Stripe log record.", file=sys.stderr)
                buffer = ""
                continue
            try:
                payload, _ = decoder.raw_decode(buffer.lstrip())
            except json.JSONDecodeError:
                continue
            buffer = ""
            if not isinstance(payload, dict):
                continue
            # Forward only the CLI's documented metadata fields, never bodies/errors.
            safe = {k: payload.get(k) for k in ("created_at", "livemode", "method", "request_id", "status", "url")}
            if isinstance(safe["url"], str):
                safe["url"] = urlsplit(safe["url"]).path
            safe["account_confirmed"] = True
            headers = {"Content-Type": "application/json"}
            ingest_token = env.get("STRIPE_LOG_INGEST_TOKEN")
            if ingest_token:
                headers["Authorization"] = f"Bearer {ingest_token}"
            outcome = None
            for attempt in range(5):
                request = urllib.request.Request(endpoint, data=json.dumps(safe).encode(), method="POST", headers=headers)
                try:
                    with urllib.request.urlopen(request, timeout=10) as response:
                        outcome = json.load(response).get("status", "unknown")
                    break
                except urllib.error.HTTPError as exc:
                    print(f"Backend rejected request metadata (HTTP {exc.code}); check incident mode and ingest token.", file=sys.stderr)
                    break
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    if attempt == 4:
                        print(f"Could not save request metadata ({type(exc).__name__}); backend may be offline.", file=sys.stderr)
                    else:
                        time.sleep(2 ** attempt)
            if outcome is not None:
                print(f"Request metadata: {outcome}", flush=True)
    except KeyboardInterrupt:
        print("\nStopping request-log stream.")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return proc.returncode if proc.returncode and proc.returncode > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
