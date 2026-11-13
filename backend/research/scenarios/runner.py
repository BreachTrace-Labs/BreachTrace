"""
CLI:  python -m research.scenarios list --platform azure
      python -m research.scenarios run --platform azure --class data
      python -m research.scenarios run --platform azure --id AZ-DATA-01
      python -m research.scenarios run --platform azure --all
Run from the backend/ directory (the API must be running on API_BASE_URL).
"""
from __future__ import annotations

import argparse
import importlib
import os
import pkgutil

ALIASES = {"recon": "RECON", "data": "DATA", "exfil": "EXFIL", "abuse": "ABUSE", "privesc": "PRIVESC",
           "code": "CODE", "comm": "COMM", "fin": "FIN", "bulk": "BULK"}


def load(platform: str) -> list:
    pkg = importlib.import_module(f"research.scenarios.{platform}")
    out = []
    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name.startswith("_"):
            continue
        out.append(importlib.import_module(f"{pkg.__name__}.{m.name}").SCENARIO)
    return sorted(out, key=lambda c: c.id)


def main() -> None:
    p = argparse.ArgumentParser(prog="research.scenarios")
    p.add_argument("cmd", choices=["list", "run"])
    p.add_argument("--platform", required=True)
    p.add_argument("--class", dest="klass", choices=sorted(ALIASES))
    p.add_argument("--id")
    p.add_argument("--all", action="store_true")
    p.add_argument("--no-record", action="store_true")
    a = p.parse_args()

    classes = load(a.platform)
    if a.id:
        classes = [c for c in classes if c.id == a.id.upper()]
    elif a.klass:
        classes = [c for c in classes if f"-{ALIASES[a.klass]}-" in c.id]
    elif not a.all and a.cmd == "run":
        p.error("choose --class, --id or --all")

    if a.cmd == "list":
        for c in classes:
            print(f"{c.id:14} {c.impact_class:28} mode={c.mode:24} blind={c.expected_blind}")
        return

    api = os.getenv("API_BASE_URL", "http://localhost:8000")
    for c in classes:
        s = c()
        print(f"\n=== {s.id} ({s.impact_class}) ===")
        try:
            res = s.run(api, record=not a.no_record)
        except Exception as exc:  # one failed scenario must not stop the batch
            print(f"FAIL ({type(exc).__name__}: {str(exc)[:160]})")
            continue
        print("PASS" if res.success else "FAIL")
        for k, v in s.report.items():
            print(f"  {k}: {v}")
        for n in res.notes:
            print(f"  - {n}")


if __name__ == "__main__":
    main()
