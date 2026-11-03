"""
Build the distillation dataset for the specialised report model.

Two steps, both resumable:

  1. facts — synthesise incidents from the real taxonomies, run them through the
     real classifier, scorer and fact-sheet builder, and split train/val/test:

        python -m research.report_distill facts --n 3000 --out ../data/report_facts.jsonl

  2. teach — a large teacher model writes the prose for each fact sheet using
     the SAME prompt the shipped model will see (reporter/prompt.py). Each
     draft must pass the grounding validator; with --drafts > 1 a judge keeps
     the best valid draft:

        GEMINI_API_KEY=... python -m research.report_distill teach \\
            --facts ../data/report_facts.jsonl --out ../data/report_sft.jsonl

     Teachers default to the Gemini Flash family (rotated; override with
     --teacher or GEMINI_TEACHER_MODELS). Interrupt any time; it resumes.

The output is TRL "prompt-completion" chat format, so training computes loss
on the report only (research/report_train.py).

Synthetic incidents cover every Tier-1 platform, empty incidents, multi-
category attacks, multi-currency Stripe money and high-volume Twilio abuse —
the edge cases the quality gate in research/report_eval.py tests.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from classifier.rules import classify_events
from classifier.taxonomy_aws import AWS_API_TAXONOMY
from classifier.taxonomy_azure import AZURE_API_TAXONOMY
from classifier.taxonomy_gcp import GCP_API_TAXONOMY
from classifier.taxonomy_stripe import STRIPE_API_TAXONOMY
from classifier.taxonomy_twilio import TWILIO_API_TAXONOMY
from normalizer.schema import ForensicEvent
from reporter.facts import build_fact_sheet
from reporter.prompt import PROMPT_VERSION, build_messages
from scorer.severity import score_incident

logger = logging.getLogger(__name__)

PLATFORMS = ("aws", "gcp", "azure", "stripe", "twilio")
_TAXONOMIES = {
    "aws": AWS_API_TAXONOMY, "gcp": GCP_API_TAXONOMY, "azure": AZURE_API_TAXONOMY,
    "stripe": STRIPE_API_TAXONOMY, "twilio": TWILIO_API_TAXONOMY,
}
_CREDENTIALS = {
    "aws": ("aws_access_key", "AKIA****{}"),
    "gcp": ("gcp_service_account", "ci-deploy..."),
    "azure": ("azure_service_principal", "3f2a91c0..."),
    "stripe": ("stripe_secret_key", "sk_live_****{}"),
    "twilio": ("twilio_account_sid", "AC3f9a1c****{}"),
}
_SPLITS = (("train", 0.85), ("val", 0.05), ("test", 0.10))

# Target severity -> categories an incident may draw actions from.
_SCENARIOS = {
    "low": {"reconnaissance"},
    "medium": {"reconnaissance", "data_access", "communication_abuse"},
    "high": {"reconnaissance", "data_access", "resource_abuse", "communication_abuse"},
    "critical": {"reconnaissance", "data_access", "resource_abuse", "communication_abuse",
                 "financial_abuse", "privilege_escalation", "exfiltration", "code_compromise"},
}


# ---------------------------------------------------------------------------
# Synthetic incidents
# ---------------------------------------------------------------------------

def _ip(rng: random.Random) -> str:
    return f"{rng.choice([45, 103, 185, 194, 31, 92, 154])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _resource(platform: str, action: str, rng: random.Random) -> str | None:
    word = rng.choice(["prod", "backup", "customer", "billing", "analytics", "staging", "media", "logs"])
    if platform == "aws":
        service = action.split(":")[0]
        return {
            "s3": f"{word}-data-{rng.randint(1, 99)}/export_{rng.randint(2023, 2026)}.csv",
            "ec2": f"i-0{rng.getrandbits(40):010x}",
            "iam": rng.choice(["root", "ci-deploy", f"svc-{word}"]),
            "rds": f"{word}-db-{rng.randint(1, 9)}",
        }.get(service, f"{word}-{service}-{rng.randint(1, 99)}")
    if platform == "gcp":
        return f"projects/{word}-{rng.randint(100, 999)}/{rng.choice(['buckets', 'instances'])}/{word}-{rng.randint(1, 9)}"
    if platform == "azure":
        return f"/subscriptions/0f3c/resourceGroups/{word}-rg/providers/{action.rsplit('/', 2)[0]}/{word}{rng.randint(1, 9)}"
    if platform == "stripe":
        prefix = action.split(".")[0]
        short = {"charge": "ch", "payment_intent": "pi", "payout": "po", "refund": "re", "customer": "cus",
                 "transfer": "tr", "invoice": "in"}.get(prefix, prefix[:3])
        return f"{short}_{rng.getrandbits(48):012x}"
    if platform == "twilio":
        return f"+{rng.choice([1, 44, 91, 234, 880, 62])}{rng.randint(10**8, 10**10 - 1)}"
    return None


def _event(platform: str, key: str, rng: random.Random, when: datetime, *, resource: str | None,
           ip: str | None, currency: str) -> ForensicEvent:
    raw: dict = {}
    action, source = key, f"{platform}.example"
    if platform == "aws":
        service, action = key.split(":", 1)
        source = f"{service}.amazonaws.com"
    elif platform == "gcp":
        source = f"{key.split('.')[0]}.googleapis.com"
    elif platform == "azure":
        source = "management.azure.com"
    elif platform == "stripe":
        source = "api.stripe.com"
        amount = rng.choice([500, 999, 2500, 4999, 12000, 41250, 99900])
        raw = {"type": key, "data": {"object": {"id": resource, "object": key.split(".")[0],
                                                "amount": amount, "currency": currency}}}
    elif platform == "twilio":
        source = "api.twilio.com"
        raw = {"price": rng.choice([0.0079, 0.0083, 0.05, 0.12, None])}
    return ForensicEvent(
        platform=platform, timestamp=when, api_action=action, event_source=source,
        source_ip=ip, affected_resource=resource, success=rng.random() > 0.12, raw_data=raw,
    )


def synth_incident(rng: random.Random, index: int) -> dict:
    platform = PLATFORMS[index % len(PLATFORMS)]
    taxonomy = _TAXONOMIES[platform]
    start = datetime(2026, rng.randint(1, 9), rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59),
                     tzinfo=timezone.utc)
    exposure = rng.choice([45, 300, 1351, 3600, 7200, 86_400, 3 * 86_400])

    events: list[ForensicEvent] = []
    if rng.random() > 0.10:  # 10% empty incidents — the hardest case to word honestly
        # Aim each incident at a severity level so the dataset is not dominated
        # by Critical (sampling the whole taxonomy gave ~65% Critical, because
        # any privilege-escalation action makes an incident Critical).
        allowed = _SCENARIOS[rng.choice(sorted(_SCENARIOS))]
        pool = sorted(k for k, v in taxonomy.items() if v["category"] in allowed) or sorted(taxonomy)
        keys = rng.sample(pool, k=min(len(pool), rng.randint(1, 6)))
        ips = [_ip(rng) for _ in range(rng.randint(1, 3))] if platform in ("aws", "gcp", "azure") else [None]
        currency = rng.choice(["usd", "usd", "usd", "eur", "gbp"])
        for key in keys:
            bulk = platform == "twilio" and key.startswith("message.") and rng.random() < 0.3
            count = rng.randint(200, 1500) if bulk else rng.choice([1, 1, 1, 2, 3, 5, 8])
            resources = [_resource(platform, key, rng) for _ in range(rng.randint(1, 3))]
            offset = rng.randint(0, max(1, exposure - 1))
            for n in range(count):
                when = start + timedelta(seconds=min(exposure, offset + n * rng.randint(1, 20)))
                events.append(_event(platform, key, rng, when, resource=rng.choice(resources),
                                     ip=rng.choice(ips), currency=currency))

    classify_events(events)
    ctype, hint = _CREDENTIALS[platform]
    facts = build_fact_sheet(
        events, platform=platform, overall_severity=score_incident(events),
        exposure_duration_seconds=exposure, credential_type=ctype,
        credential_hint=hint.format(f"{rng.getrandbits(16):04x}"),
    )
    return facts


def _split(rng: random.Random) -> str:
    roll, total = rng.random(), 0.0
    for name, share in _SPLITS:
        total += share
        if roll < total:
            return name
    return "train"


def cmd_facts(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for i in range(args.n):
            facts = synth_incident(rng, i)
            fh.write(json.dumps({"id": f"syn-{i:05d}", "split": _split(rng),
                                 "prompt_version": PROMPT_VERSION, "facts": facts}) + "\n")
    print(f"wrote {args.n} fact sheets to {out}")


# ---------------------------------------------------------------------------
# Teacher
# ---------------------------------------------------------------------------

class DailyQuotaExhausted(RuntimeError):
    """Every teacher model has hit its per-day quota; re-run later to resume."""


class TeacherPool:
    """
    Rotates across teacher models with retry and backoff.

    Free-tier Gemini returns 503 (overloaded) often and 429 when a per-minute or
    per-day quota is hit. Each model has its own quota, so rotating across the
    Flash family both rides out overload and multiplies daily capacity.
    """

    def __init__(self, models: list[str], *, max_attempts: int = 6) -> None:
        from reporter.writers import gemini_writer

        self.writers = {}
        for model in models:
            writer = gemini_writer(model)
            if writer is not None:
                self.writers[model] = writer
        if not self.writers:
            raise SystemExit("Teacher unavailable: set GEMINI_API_KEY and `pip install google-genai`")
        self.exhausted: set[str] = set()
        self.max_attempts = max_attempts
        self._lock = threading.Lock()
        self._turn = 0

    def _next_model(self) -> str:
        with self._lock:
            live = [m for m in self.writers if m not in self.exhausted]
            if not live:
                raise DailyQuotaExhausted("all teacher models hit their daily quota")
            self._turn += 1
            return live[self._turn % len(live)]

    def write(self, facts: dict) -> tuple[dict | None, str]:
        delay = 5.0
        for _ in range(self.max_attempts):
            model = self._next_model()
            try:
                return self.writers[model](facts, None), model
            except Exception as exc:  # SDK errors carry the HTTP status in the text
                message = str(exc)
                if "429" in message and ("PerDay" in message or "per day" in message.lower()):
                    logger.warning("daily quota reached for %s", model)
                    with self._lock:
                        self.exhausted.add(model)
                    continue
                if any(code in message for code in ("429", "500", "503", "504", "UNAVAILABLE", "DEADLINE")):
                    time.sleep(delay + random.random() * 2)
                    delay = min(delay * 2, 120)
                    continue
                raise
        return None, ""


def cmd_teach(args: argparse.Namespace) -> None:
    from reporter.validate import validate_sections
    from research.report_eval import judge_pair

    pool = TeacherPool([m.strip() for m in args.teacher.split(",") if m.strip()])

    out = Path(args.out)
    done = set()
    if out.exists():
        done = {json.loads(line)["id"] for line in out.open(encoding="utf-8")}

    todo = []
    with Path(args.facts).open(encoding="utf-8") as src:
        for line in src:
            row = json.loads(line)
            if row["id"] not in done and (not args.splits or row["split"] in args.splits):
                todo.append(row)
    print(f"{len(done)} already taught, {len(todo)} to go, teachers: {', '.join(pool.writers)}")

    lock = threading.Lock()
    stats = {"kept": 0, "rejected": 0}

    def teach_one(row: dict) -> None:
        facts = row["facts"]
        drafts = []
        teacher = ""
        for _ in range(args.drafts):
            sections, model = pool.write(facts)
            if sections and not validate_sections(sections, facts):
                drafts.append(sections)
                teacher = teacher or model
        if not drafts:
            with lock:
                stats["rejected"] += 1  # left out of the file, so a re-run retries it
            return

        best = drafts[0]
        for challenger in drafts[1:]:
            if judge_pair(facts, best, challenger, judge_model=args.judge) == "B":
                best = challenger

        record = json.dumps({
            "id": row["id"], "split": row["split"], "prompt_version": PROMPT_VERSION,
            "teacher": teacher,
            "prompt": build_messages(facts),
            "completion": [{"role": "assistant", "content": json.dumps(best, ensure_ascii=False)}],
        }, ensure_ascii=False)
        with lock:
            with out.open("a", encoding="utf-8") as dst:
                dst.write(record + "\n")
            stats["kept"] += 1
            if stats["kept"] % 25 == 0:
                print(f"kept {stats['kept']}, rejected {stats['rejected']}", flush=True)

    from concurrent.futures import ThreadPoolExecutor

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for future in [executor.submit(teach_one, row) for row in todo]:
                future.result()
    except DailyQuotaExhausted:
        print("Daily quota reached on every teacher model. Re-run the same command later; it resumes.")
    print(f"done: kept {stats['kept']}, rejected {stats['rejected']} (rejected rows are retried on re-run)")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    facts = sub.add_parser("facts", help="synthesise fact sheets")
    facts.add_argument("--n", type=int, default=3000)
    facts.add_argument("--seed", type=int, default=7)
    facts.add_argument("--out", required=True)
    facts.set_defaults(func=cmd_facts)

    teach = sub.add_parser("teach", help="teacher-written targets for each fact sheet")
    teach.add_argument("--facts", required=True)
    teach.add_argument("--out", required=True)
    teach.add_argument(
        "--teacher",
        default=os.getenv("GEMINI_TEACHER_MODELS", "gemini-3.5-flash,gemini-3.8-flash,gemini-3.6-flash"),
        help="comma-separated; rotated for overload and per-model quotas",
    )
    teach.add_argument("--judge", default=os.getenv("GEMINI_JUDGE_MODEL", "gemini-3.5-flash"),
                       help="picks the best of --drafts")
    teach.add_argument("--workers", type=int, default=3, help="parallel teacher calls")
    teach.add_argument("--drafts", type=int, default=1)
    teach.add_argument("--splits", nargs="*", default=["train", "val"],
                       help="test is held out for report_eval and never taught")
    teach.set_defaults(func=cmd_teach)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
