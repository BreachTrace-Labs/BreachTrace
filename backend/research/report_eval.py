"""
Quality gate: the local report model must match Gemini before it ships.

Runs on the held-out TEST split of research/report_distill.py fact sheets,
which the model never saw in training. Steps:

  1. generate — each candidate writes every test report; outputs are cached.
        python -m research.report_eval generate --facts ../data/report_facts.jsonl \\
            --writer local:/path/breachtrace-reporter-q4_k_m.gguf --out ../data/eval_local.jsonl
        python -m research.report_eval generate --facts ../data/report_facts.jsonl \\
            --writer gemini:gemini-3.5-flash --out ../data/eval_gemini.jsonl

  2. judge — blind pairwise LLM judging, both orders (position-bias control).
        python -m research.report_eval judge --a ../data/eval_local.jsonl \\
            --b ../data/eval_gemini.jsonl --out ../data/judge.jsonl

  3. human-sheet / human-score — blind A/B sheet for team raters, then scoring.
        python -m research.report_eval human-sheet --a ... --b ... --n 40 --out ../data/human.csv
        python -m research.report_eval human-score --sheet ../data/human_filled.csv \
            --key ../data/human.csv.key.json

  4. gate — every criterion from the plan, PASS/FAIL, saved as JSON.
        python -m research.report_eval gate --candidate ../data/eval_local.jsonl \\
            --reference ../data/eval_gemini.jsonl --judge ../data/judge.jsonl \\
            [--human ../data/human_filled.csv --human-key ../data/human.csv.key.json] \
            --model /path/breachtrace-reporter-q4_k_m.gguf

     Only a PASS writes a manifest the runtime accepts; ship it next to the model.

Pass bars (plan §1.5): grounding >= reference and >= 98%; fact coverage >=
reference; judge and human win-or-tie vs reference >= 50%; p95 latency <= 15 s
and peak RAM <= 1 GB on a CPU-only laptop.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import resource
import statistics
import sys
import time
from pathlib import Path

from reporter.compose import deterministic_sections
from reporter.validate import validate_sections

GROUNDING_MIN = 0.98
WIN_OR_TIE_MIN = 0.50
P95_LATENCY_MAX_S = 15.0
PEAK_RAM_MAX_MB = 1024


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _prose(sections: dict) -> str:
    return " ".join([sections["executive_summary"], *sections["narrative"], sections["business_impact"]]).lower()


def fact_coverage(sections: dict, facts: dict) -> float:
    """
    Share of the key facts a reader needs that the prose actually states:
    severity, exposure duration, the most serious action, the top resource and
    the first money figure. Only facts present in the sheet count.
    """
    text = _prose(sections)
    checks: list[bool] = [facts["severity"].lower() in text]

    duration = facts["exposure_duration"].split(" ")
    checks.append(" ".join(duration[:2]).lower() in text)

    if facts["actions"]:
        top = facts["actions"][0]
        names = [top["action"].lower(), (top.get("label") or "").lower()]
        checks.append(any(n and n in text for n in names))
    if facts["resources"]:
        checks.append(facts["resources"][0].lower() in text)
    if facts["financial"]:
        amount = re.search(r"\d[\d,]*\.\d{2}", facts["financial"][0])
        if amount:
            checks.append(amount.group(0) in text or amount.group(0).replace(",", "") in text)
    return sum(checks) / len(checks)


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))]


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def _make_writer(spec: str):
    kind, _, arg = spec.partition(":")
    if kind == "deterministic":
        return lambda facts, feedback=None: deterministic_sections(facts)
    if kind == "local":
        from reporter.local_model import LocalReportModel

        model = LocalReportModel(arg, idle_seconds=0)
        return model.generate
    if kind == "gemini":
        from reporter.writers import gemini_writer

        from research.report_distill import TeacherPool

        pool = TeacherPool([arg] if arg else ["gemini-3.5-flash"])  # retries overload/quota
        return lambda facts, feedback=None: pool.write(facts)[0] if feedback is None else \
            pool.writers[next(iter(pool.writers))](facts, feedback)
    raise SystemExit(f"unknown writer {spec!r}; use deterministic | local:<gguf> | gemini:<model>")


def cmd_generate(args: argparse.Namespace) -> None:
    from reporter.writers import write_validated

    writer = _make_writer(args.writer)
    out = Path(args.out)
    done = {json.loads(l)["id"] for l in out.open(encoding="utf-8")} if out.exists() else set()
    with Path(args.facts).open(encoding="utf-8") as src, out.open("a", encoding="utf-8") as dst:
        for line in src:
            row = json.loads(line)
            if row["split"] != "test" or row["id"] in done:
                continue
            facts = row["facts"]
            started = time.monotonic()
            first = writer(facts, None)  # first-attempt quality, before any retry
            first_violations = validate_sections(first, facts) if first else ["unparseable"]
            final, violations = (first, []) if not first_violations else write_validated(writer, facts)
            dst.write(json.dumps({
                "id": row["id"], "writer": args.writer, "facts": facts,
                "sections": final or deterministic_sections(facts),
                "fell_back": final is None,
                "first_attempt_grounded": not first_violations,
                "grounded": final is not None,
                "violations": first_violations,
                "latency_s": round(time.monotonic() - started, 2),
            }, ensure_ascii=False) + "\n")
            dst.flush()
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1e6 if sys.platform == "darwin" else 1e3)
    Path(str(out) + ".meta.json").write_text(json.dumps({"writer": args.writer, "peak_rss_mb": round(peak_mb)}))
    print(f"done; peak RSS {peak_mb:.0f} MB")


# ---------------------------------------------------------------------------
# Pairwise judging
# ---------------------------------------------------------------------------

JUDGE_PROMPT = """You are judging two drafts of the same credential-leak incident report.
The FACT SHEET is the ground truth. The reader is a developer with no security background.

Judge on, in order of importance:
1. Accuracy: every statement is supported by the fact sheet; nothing invented, nothing wrong.
2. Completeness: the important facts (what leaked, how long, what was done, severity, money, compliance) are stated.
3. Clarity and usefulness for the reader.

Reply with JSON only: {{"winner": "A" | "B" | "tie", "reason": "<one sentence>"}}

FACT SHEET:
{facts}

DRAFT A:
{a}

DRAFT B:
{b}"""


def judge_pair(facts: dict, a: dict, b: dict, *, judge_model: str | None = None) -> str:
    """'A', 'B' or 'tie'. Judged in both orders; a split decision is a tie."""
    import config
    from google import genai

    client = genai.Client(api_key=config.GEMINI_API_KEY)
    judge_model = judge_model or os.getenv("GEMINI_JUDGE_MODEL", "gemini-3.5-flash")

    def ask(first: dict, second: dict) -> str:
        prompt = JUDGE_PROMPT.format(
            facts=json.dumps(facts, ensure_ascii=False),
            a=json.dumps(first, ensure_ascii=False),
            b=json.dumps(second, ensure_ascii=False),
        )
        response = None
        for attempt in range(6):  # free-tier overload is routine; back off and retry
            try:
                response = client.models.generate_content(
                    model=judge_model, contents=prompt,
                    config={"response_mime_type": "application/json", "temperature": 0},
                )
                break
            except Exception as exc:
                if not any(c in str(exc) for c in ("429", "500", "503", "504", "UNAVAILABLE")):
                    raise
                time.sleep(min(5 * 2 ** attempt, 120))
        try:
            return json.loads(response.text).get("winner", "tie")
        except (ValueError, AttributeError):
            return "tie"

    forward = ask(a, b)
    backward = {"A": "B", "B": "A"}.get(ask(b, a), "tie")
    return forward if forward == backward else "tie"


def _load(path: str) -> dict[str, dict]:
    return {r["id"]: r for r in map(json.loads, Path(path).open(encoding="utf-8"))}


def cmd_judge(args: argparse.Namespace) -> None:
    a, b = _load(args.a), _load(args.b)
    out = Path(args.out)
    done = {json.loads(l)["id"] for l in out.open(encoding="utf-8")} if out.exists() else set()
    with out.open("a", encoding="utf-8") as dst:
        for rid in sorted(set(a) & set(b) - done):
            verdict = judge_pair(a[rid]["facts"], a[rid]["sections"], b[rid]["sections"], judge_model=args.judge)
            dst.write(json.dumps({"id": rid, "verdict": verdict, "a": args.a, "b": args.b}) + "\n")
            dst.flush()
            time.sleep(args.sleep)


# ---------------------------------------------------------------------------
# Human rating
# ---------------------------------------------------------------------------

def _render(sections: dict) -> str:
    return "\n".join([sections["executive_summary"], "", *[f"- {s}" for s in sections["narrative"]], "",
                      sections["business_impact"]])


def cmd_human_sheet(args: argparse.Namespace) -> None:
    """Blind sheet: raters see Draft 1 / Draft 2 in random order; the key is a separate file."""
    a, b = _load(args.a), _load(args.b)
    rng = random.Random(args.seed)
    ids = rng.sample(sorted(set(a) & set(b)), k=min(args.n, len(set(a) & set(b))))
    key = {}
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "facts", "draft_1", "draft_2", "preferred (1/2/tie)", "notes"])
        for rid in ids:
            swap = rng.random() < 0.5
            first, second = (b, a) if swap else (a, b)
            key[rid] = "b_first" if swap else "a_first"
            writer.writerow([rid, json.dumps(a[rid]["facts"], ensure_ascii=False, indent=1),
                             _render(first[rid]["sections"]), _render(second[rid]["sections"]), "", ""])
    Path(args.out + ".key.json").write_text(json.dumps(key, indent=1))
    print(f"wrote {len(ids)} pairs to {args.out}; keep {args.out}.key.json away from raters")


def human_win_or_tie(sheet: str, key_path: str) -> tuple[float, int]:
    """Candidate (A) win-or-tie rate from a filled sheet and the key written with it."""
    key = json.loads(Path(key_path).read_text())
    good = total = 0
    for row in csv.DictReader(open(sheet, encoding="utf-8")):
        choice = (row.get("preferred (1/2/tie)") or "").strip().lower()
        if choice not in ("1", "2", "tie"):
            continue
        total += 1
        a_slot = "1" if key[row["id"]] == "a_first" else "2"
        good += choice in ("tie", a_slot)
    return (good / total if total else 0.0), total


def cmd_human_score(args: argparse.Namespace) -> None:
    rate, n = human_win_or_tie(args.sheet, args.key)
    print(f"candidate win-or-tie (human): {rate:.1%} over {n} rated pairs")


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def summarise(path: str) -> dict:
    rows = list(_load(path).values())
    meta_path = Path(path + ".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    latencies = [r["latency_s"] for r in rows]
    return {
        "n": len(rows),
        "grounding": sum(r["first_attempt_grounded"] for r in rows) / len(rows),
        "grounding_after_retry": sum(r["grounded"] for r in rows) / len(rows),
        "fact_coverage": statistics.mean(fact_coverage(r["sections"], r["facts"]) for r in rows),
        "p95_latency_s": _percentile(latencies, 95),
        "peak_rss_mb": meta.get("peak_rss_mb"),
    }


def cmd_gate(args: argparse.Namespace) -> None:
    cand, ref = summarise(args.candidate), summarise(args.reference)
    verdicts = [json.loads(l)["verdict"] for l in open(args.judge, encoding="utf-8")] if args.judge else []
    judge_rate = sum(v in ("A", "tie") for v in verdicts) / len(verdicts) if verdicts else None
    human_rate, human_n = human_win_or_tie(args.human, args.human_key) if args.human else (None, 0)

    checks = {
        "grounding >= reference and >= 98%":
            cand["grounding"] >= max(ref["grounding"], GROUNDING_MIN),
        "fact coverage >= reference": cand["fact_coverage"] >= ref["fact_coverage"],
        "judge win-or-tie >= 50%": judge_rate is not None and judge_rate >= WIN_OR_TIE_MIN,
        "human win-or-tie >= 50%": human_rate is not None and human_rate >= WIN_OR_TIE_MIN,
        "p95 latency <= 15 s": cand["p95_latency_s"] <= P95_LATENCY_MAX_S,
        "peak RAM <= 1 GB": cand["peak_rss_mb"] is not None and cand["peak_rss_mb"] <= PEAK_RAM_MAX_MB,
    }
    result = {
        "candidate": cand, "reference": ref,
        "judge_win_or_tie": judge_rate, "judge_n": len(verdicts),
        "human_win_or_tie": human_rate, "human_n": human_n,
        "checks": checks, "passed": all(checks.values()),
    }
    print(json.dumps(result, indent=2))
    print("\nGATE:", "PASS" if result["passed"] else "FAIL")
    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2))
    if args.model:
        # The manifest the runtime checks before it will use this model file.
        from reporter.local_model import _file_sha256, gate_manifest_path

        manifest = {**result, "model_sha256": _file_sha256(args.model)}
        Path(gate_manifest_path(args.model)).write_text(json.dumps(manifest, indent=2))
        print(f"wrote {gate_manifest_path(args.model)} (passed={result['passed']})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("generate"); p.set_defaults(func=cmd_generate)
    p.add_argument("--facts", required=True); p.add_argument("--writer", required=True); p.add_argument("--out", required=True)

    p = sub.add_parser("judge"); p.set_defaults(func=cmd_judge)
    p.add_argument("--a", required=True, help="candidate outputs"); p.add_argument("--b", required=True, help="reference outputs")
    p.add_argument("--judge", default=None, help="default: $GEMINI_JUDGE_MODEL or gemini-3.5-flash")
    p.add_argument("--out", required=True)
    p.add_argument("--sleep", type=float, default=1.0)

    p = sub.add_parser("human-sheet"); p.set_defaults(func=cmd_human_sheet)
    p.add_argument("--a", required=True); p.add_argument("--b", required=True)
    p.add_argument("--n", type=int, default=40); p.add_argument("--seed", type=int, default=11); p.add_argument("--out", required=True)

    p = sub.add_parser("human-score"); p.set_defaults(func=cmd_human_score)
    p.add_argument("--sheet", required=True)
    p.add_argument("--key", required=True, help="the .key.json written by human-sheet")

    p = sub.add_parser("gate"); p.set_defaults(func=cmd_gate)
    p.add_argument("--candidate", required=True); p.add_argument("--reference", required=True)
    p.add_argument("--judge"); p.add_argument("--human"); p.add_argument("--human-key")
    p.add_argument("--out")
    p.add_argument("--model", help="the candidate GGUF; writes <model>.gate.json for the runtime")

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
