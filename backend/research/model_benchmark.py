"""Reproducible local multi-model report benchmark; no downloads or cloud calls.

PYTHONPATH=backend python -m research.model_benchmark --model llama3.2:latest \
    --model qwen2.5vl:3b --cases 6 --out data/model-benchmark.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time

import requests

from llm_client import generate
from model_settings import ModelSettings
from reporter.compose import deterministic_sections
from reporter.prompt import PROMPT_VERSION, build_messages, parse_sections
from reporter.validate import validate_sections
from research.report_distill import synth_incident
from research.report_eval import fact_coverage


def summarize(rows):
    latencies = sorted(row["latency_s"] for row in rows)
    n = len(rows)
    return {"n": n, "valid_json_rate": sum(r["valid_json"] for r in rows) / n if n else None,
            "grounding_pass_rate": sum(r["grounded"] for r in rows) / n if n else None,
            "mean_fact_coverage": statistics.mean(r["fact_coverage"] for r in rows) if n else None,
            "median_latency_s": statistics.median(latencies) if n else None,
            "p95_latency_s": latencies[math.ceil(.95 * n) - 1] if n else None,
            "failures": sum(bool(r.get("error_type")) for r in rows)}


def hardware():
    ram = None
    if platform.system() == "Darwin":
        try:
            ram = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
        except (OSError, ValueError, subprocess.CalledProcessError):
            pass
    else:
        try:
            ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (OSError, ValueError):
            pass
    return {"os": platform.system(), "architecture": platform.machine(), "cpu_count": os.cpu_count(),
            "ram_gb": round(ram / 1024 ** 3, 1) if ram else None,
            "python": platform.python_version()}


def run(models, count, seed, out):
    rng = random.Random(seed)
    facts = [synth_incident(rng, index) for index in range(count)]
    try:
        installed = requests.get("http://127.0.0.1:11434/api/tags", timeout=5).json()["models"]
    except (requests.RequestException, KeyError, ValueError):
        raise SystemExit("Start Ollama and install candidate models before benchmarking") from None
    by_name = {item["name"]: item for item in installed}
    if any(name not in by_name for name in models):
        raise SystemExit("A requested model is not installed; no model will be downloaded")
    result = {"hardware": hardware(), "prompt_version": PROMPT_VERSION, "seed": seed,
              "fixture_kind": "synthetic-first-attempt-report-facts",
              "fixture_sha256": hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest(),
              "scope": "Pilot only; validator grounding and fact coverage are proxies, not human accuracy or RAG accuracy. Latency includes model loading; no retries or fallback outputs counted as model success.",
              "models": {}}
    # Template baseline uses exactly the same facts.
    baseline = []
    for fact in facts:
        start = time.perf_counter(); sections = deterministic_sections(fact)
        baseline.append({"latency_s": time.perf_counter() - start, "valid_json": True,
                         "grounded": not validate_sections(sections, fact), "fact_coverage": fact_coverage(sections, fact)})
    result["deterministic_baseline"] = summarize(baseline)
    out = Path(out); out.parent.mkdir(parents=True, exist_ok=True)

    def save():
        out.write_text(json.dumps(result, indent=2) + "\n")

    save()
    for name in models:
        settings = ModelSettings(provider="ollama", model=name, timeout_s=180)
        rows = []
        result["models"][name] = {"digest": by_name[name].get("digest"),
                                  "model_file_bytes": by_name[name].get("size"), "rows": rows}
        for index, fact in enumerate(facts):
            start = time.perf_counter()
            row = {"case": index, "platform": fact["platform"], "valid_json": False,
                   "grounded": False, "fact_coverage": 0.0}
            try:
                sections = parse_sections(generate(settings, build_messages(fact), json_output=True))
                row["valid_json"] = sections is not None
                row["violations"] = validate_sections(sections, fact) if sections else ["unparseable JSON sections"]
                row["grounded"] = not row["violations"]
                row["fact_coverage"] = fact_coverage(sections, fact) if sections else 0.0
                row["sections"] = sections
            except Exception as exc:
                row["error_type"] = type(exc).__name__
            row["latency_s"] = round(time.perf_counter() - start, 3)
            rows.append(row)
            result["models"][name]["summary"] = summarize(rows)
            # Ollama-reported allocation, not controller RSS or measured peak RAM.
            try:
                loaded = requests.get("http://127.0.0.1:11434/api/ps", timeout=5).json()["models"]
                row["ollama_allocation"] = [{k: m.get(k) for k in ["name", "size", "size_vram"]} for m in loaded if m.get("name") == name]
            except (requests.RequestException, ValueError, KeyError):
                row["ollama_allocation"] = None
            save()
            print(f"{name}: {index + 1}/{count}; grounded={row['grounded']}; {row['latency_s']}s", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--cases", type=int, default=6)
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if not 1 <= args.cases <= 1000:
        parser.error("--cases must be between 1 and 1000")
    run(args.model, args.cases, args.seed, args.out)


if __name__ == "__main__":
    main()
