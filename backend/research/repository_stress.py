"""Scan existing public checkouts and record pinned performance, without executing code.

PYTHONPATH=backend python -m research.repository_stress /path/to/repo --out data/stress.json
"""
import argparse
import json
from pathlib import Path
import platform
import subprocess

from detector.repository import ScanLimits, scan_repository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=ScanLimits().timeout_s)
    args = parser.parse_args()
    root = args.root.resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    result = scan_repository(root, ScanLimits(timeout_s=args.timeout))
    result.update({"revision": revision, "os": platform.system(), "architecture": platform.machine(),
                   "study_limit": "Unlabelled public code: candidates are not confirmed leaks. Precision/recall cannot be computed without independent labels."})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "findings"}, indent=2))


if __name__ == "__main__":
    main()
