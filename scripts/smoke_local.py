"""Exercise the running local test stack without cloud credentials or paid APIs."""
from datetime import datetime, timezone
import json
from pathlib import Path
import time

import requests


BASE = "http://127.0.0.1:8000"


def get(path):
    response = requests.get(BASE + path, timeout=60)
    response.raise_for_status()
    return response.json()


def post(path, body):
    response = requests.post(BASE + path, json=body, timeout=60)
    response.raise_for_status()
    return response.json()


def main():
    checks = {}
    checks["backend_health"] = get("/health")["status"] == "ok"
    checks["frontend"] = requests.get("http://127.0.0.1:5173", timeout=10).status_code == 200
    incidents = get("/incidents")
    fixture = next(i for i in incidents if i["repo_url"] == "local-test://synthetic-forensic-timeline")
    detail = get("/incidents/" + fixture["incident_id"])
    checks["synthetic_timeline"] = len(detail["events"]) == 3 and "SYNTHETIC LOCAL TEST" in detail["report_text"]
    search = post("/assistant/search", {"question": "what happened at 2026-11-03T12:00:30Z", "incident_id": fixture["incident_id"]})
    checks["timestamp_search"] = len(search["passages"]) == 1 and "GetObject" in search["passages"][0]["text"]
    knowledge = post("/assistant/search", {"question": "how do I rotate a Twilio auth token"})
    checks["knowledge_search"] = bool(knowledge["passages"])
    checks["semantic_search"] = get("/assistant/status")["semantic_search"]
    checks["model_settings"] = get("/settings/model")["provider"] in {"none", "ollama", "local", "openai", "anthropic", "gemini"}
    checks["hardware"] = get("/settings/model/hardware")["ram_gb"] is not None
    checks["research_api"] = isinstance(get("/research/export"), list)
    # Deliberately synthetic, offline-format key. Detection-only: no vendor calls.
    value = "gsk_" + ("Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU" * 2)[:52]
    created = post("/test/simulate", {"repo_url": "local-test://synthetic-ai-detection", "diff_text": "+GROQ_API_KEY=" + value})
    checks["ai_detection"] = created["incidents_created"] == 1
    ai_detail = get("/incidents/" + created["incident_id"])
    checks["ai_detection_only"] = ai_detail["forensic_tier"] == 2 and ai_detail["platform"] == "groq" and ai_detail["status"] == "complete"
    checks["ai_key_masked"] = value not in json.dumps(ai_detail)
    # Test an installed local model with a short prompt, then restore preferences.
    saved = get("/settings/model")
    settings_response = requests.put(BASE + "/settings/model", json={"provider": "ollama", "model": "llama3.2:latest", "timeout_s": 120}, timeout=10)
    settings_response.raise_for_status()
    try:
        checks["local_model_connection"] = post("/settings/model/test", {})["ok"]
    finally:
        response = requests.put(BASE + "/settings/model", json=saved, timeout=10)
        response.raise_for_status()
    # Public archive, no webhook registration or account mutation.
    scan = post("/repositories/scan", {"repo_url": "https://github.com/fastapi/fastapi"})
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        job = get("/repositories/scans/" + scan["scan_id"])
        if job["status"] not in {"queued", "scanning"}:
            break
        time.sleep(2)
    checks["snapshot_scan"] = job["status"] == "complete" and job["result"]["files_scanned"] > 3000
    result = {"at": datetime.now(timezone.utc).isoformat(), "checks": checks,
              "synthetic_incident_id": fixture["incident_id"], "ai_test_incident_id": created["incident_id"],
              "snapshot_scan_id": scan["scan_id"], "all_passed": all(checks.values())}
    target = Path(__file__).resolve().parents[1] / "data" / "local-smoke-results.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
