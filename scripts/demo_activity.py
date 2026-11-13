"""Generate fresh Stripe (test-mode) and Twilio activity right before the demo.

The collectors only look at the 120 minutes before the push, so an account with
no recent activity correctly shows an empty timeline. Run this 5-10 minutes
before pushing the leaked keys.

  Stripe: STRIPE_KEY=rk_test_... python scripts/demo_activity.py stripe
  Twilio: python scripts/demo_activity.py twilio --to +91XXXXXXXXXX --from +1XXXXXXXXXX

Twilio uses TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN from .env. The recipient must
be a number you own (a verified caller ID on a trial account).
"""
import argparse
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def stripe_activity(key: str) -> None:
    auth = (key, "")
    base = "https://api.stripe.com/v1"
    steps = [
        ("customer.created", "POST", "/customers", {"email": "attacker@example.com", "name": "Demo Attacker"}),
        ("product.created", "POST", "/products", {"name": "Exfil Test Product"}),
        ("customer.created", "POST", "/customers", {"email": "second@example.com"}),
    ]
    made = []
    for label, method, path, data in steps:
        r = httpx.request(method, base + path, data=data, auth=auth, timeout=20)
        print(f"  {label:20s} HTTP {r.status_code}", "" if r.status_code == 200 else r.json().get("error", {}).get("message", "")[:90])
        if r.status_code == 200 and path == "/customers":
            made.append(r.json()["id"])
    for cid in made[:1]:
        r = httpx.delete(f"{base}/customers/{cid}", auth=auth, timeout=20)
        print(f"  customer.deleted     HTTP {r.status_code}")
    # Reads do not create events but show the key is live.
    print("  list events:", httpx.get(base + "/events", params={"limit": 3}, auth=auth, timeout=20).status_code)


def twilio_activity(to: str, from_: str, count: int) -> None:
    sid, tok = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    for i in range(count):
        r = httpx.post(url, data={"To": to, "From": from_, "Body": f"BreachTrace demo message {i + 1}"}, auth=(sid, tok), timeout=20)
        print(f"  message {i + 1}: HTTP {r.status_code}", "" if r.status_code < 300 else r.text[:120])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("which", choices=["stripe", "twilio"])
    ap.add_argument("--to")
    ap.add_argument("--from", dest="from_")
    ap.add_argument("--count", type=int, default=3)
    a = ap.parse_args()
    if a.which == "stripe":
        k = os.environ.get("STRIPE_KEY") or os.environ.get("STRIPE_API_KEY")
        if not k:
            sys.exit("Set STRIPE_KEY=rk_test_...")
        stripe_activity(k)
    else:
        if not (a.to and a.from_):
            sys.exit("--to and --from are required")
        twilio_activity(a.to, a.from_, a.count)
