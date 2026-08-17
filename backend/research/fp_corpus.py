"""
Track A' — false-positive measurement against real open-source code.

WHY THIS EXISTS
---------------
SecretBench's labelled dataset is gated behind a signed data protection
agreement (see backend/tests/test_secretbench.py), so the planned precision
measurement against public ground truth is not available.

This is the strongest external validation obtainable without it. It measures
the number that matters most and that our hand-built fixture structurally
cannot produce: **how often the detector fires on real code that we did not
write.**

WHAT IT MEASURES — AND WHAT IT DOES NOT
---------------------------------------
Measures: false-positive rate / precision-in-the-wild. Every hit is written out
for manual adjudication; the reported figure is only meaningful once a human has
labelled each one.

Does NOT measure recall. There is no ground truth for secrets these repositories
do not contain, so this cannot tell us what we missed. Recall evidence comes
from the published-pattern parity in test_secretbench_pattern_parity.py, and
from Track B's controlled exposures.

METHODOLOGY NOTES FOR THE PAPER
-------------------------------
1. The corpus is fixed in CORPUS below and was chosen BEFORE the detector was
   run over it, deliberately biased toward config-heavy and
   credential-adjacent projects — the places secret-shaped strings actually
   live. Choosing repositories after seeing results, or choosing quiet ones,
   would manufacture a good number.
2. Repositories are pinned by commit SHA at scan time and the SHA is recorded,
   so the measurement is reproducible.
3. Every hit is emitted with file, line and surrounding context so adjudication
   is auditable rather than a bare count.
4. Test fixtures and example files inside these repos are NOT excluded. Real
   scanners face them, and a detector that only looks good with fixtures
   filtered out is not a detector worth reporting.

Usage:
    python -m research.fp_corpus --clone       # fetch the corpus (network)
    python -m research.fp_corpus --scan        # scan and emit hits for review
    python -m research.fp_corpus --report      # summarise adjudicated results
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

# Repository set. Chosen for config density and ecosystem spread, not for a
# flattering result. Each is large, real, and full of the string shapes that
# trip credential scanners: sample configs, test fixtures, docs with example
# keys, IaC templates.
CORPUS: tuple[tuple[str, str], ...] = (
    ("localstack/localstack", "AWS emulator — dense with AKIA-shaped test values"),
    ("aws/aws-cli", "AWS CLI — official examples and fixtures"),
    ("GoogleCloudPlatform/python-docs-samples", "GCP samples — service account emails everywhere"),
    ("Azure/azure-sdk-for-python", "Azure SDK — client IDs, connection strings in tests"),
    ("stripe/stripe-python", "Stripe SDK — sk_test keys in fixtures"),
    ("twilio/twilio-python", "Twilio SDK — Account SIDs in fixtures"),
    ("hashicorp/terraform-provider-aws", "IaC — credentials in acceptance tests"),
    ("kubernetes/examples", "K8s manifests — service accounts, secrets objects"),
    ("docker/awesome-compose", "Compose files — env blocks and connection strings"),
    ("gitleaks/gitleaks", "A secret scanner's own test corpus — adversarial by design"),
)

# File extensions worth scanning. Binary and vendored assets are skipped: they
# cannot contain a committed secret in a form the detector targets, and they
# dominate the byte count if included.
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".cs", ".php",
    ".sh", ".bash", ".zsh", ".ps1",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".example", ".sample", ".template", ".tf", ".tfvars",
    ".md", ".rst", ".txt", ".dockerfile",
}
SCAN_FILENAMES = {".env", "Dockerfile", "docker-compose.yml", "Makefile"}

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv"}

MAX_FILE_BYTES = 1_000_000  # skip generated blobs; nothing real is bigger


@dataclass
class Hit:
    repo: str
    commit: str
    file_path: str
    line_number: int
    credential_type: str
    platform: str
    credential_hint: str
    context: str
    # Filled in by a human during adjudication.
    verdict: str = "UNREVIEWED"   # TRUE_POSITIVE | FALSE_POSITIVE | UNREVIEWED
    note: str = ""


def _corpus_dir() -> Path:
    return Path(os.getenv("FP_CORPUS_DIR", "/tmp/breachtrace-fp-corpus"))


def clone_corpus() -> None:
    """Shallow-clone the corpus. Shallow is fine: we scan the current tree."""
    root = _corpus_dir()
    root.mkdir(parents=True, exist_ok=True)

    for repo, rationale in CORPUS:
        target = root / repo.replace("/", "__")
        if target.exists():
            print(f"  have  {repo}")
            continue
        print(f"  clone {repo}  ({rationale})")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet",
             f"https://github.com/{repo}.git", str(target)],
            check=False,
        )
    print(f"\nCorpus at {root}")


def _head_sha(repo_dir: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip()[:12] or "unknown"


def _should_scan(path: Path) -> bool:
    if path.name in SCAN_FILENAMES:
        return True
    return path.suffix.lower() in SCAN_EXTENSIONS


def scan_corpus() -> list[Hit]:
    """
    Run the full detector over every scannable file in the corpus.

    Files are passed as raw text, not as diffs. `scan()` treats a line with no
    diff marker as an addition, which is the correct reading here: we are asking
    "would this file's contents trigger an incident", which is what a first scan
    of a repository does.
    """
    from detector.scanner import scan

    root = _corpus_dir()
    if not root.exists():
        sys.exit(f"No corpus at {root}. Run with --clone first.")

    hits: list[Hit] = []
    files_scanned = 0
    bytes_scanned = 0

    for repo, _ in CORPUS:
        repo_dir = root / repo.replace("/", "__")
        if not repo_dir.exists():
            print(f"  SKIP {repo} (not cloned)")
            continue

        commit = _head_sha(repo_dir)
        repo_hits = 0

        for path in repo_dir.rglob("*"):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
                continue
            if not _should_scan(path):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            files_scanned += 1
            bytes_scanned += len(text)

            for match in scan(text, include_saas=True):
                line_no = getattr(match, "line_number", None) or 0
                lines = text.splitlines()
                context = lines[line_no - 1].strip()[:200] if 0 < line_no <= len(lines) else ""
                hits.append(Hit(
                    repo=repo,
                    commit=commit,
                    file_path=str(path.relative_to(repo_dir)),
                    line_number=line_no,
                    credential_type=match.credential_type,
                    platform=getattr(match, "platform", "aws"),
                    credential_hint=match.credential_hint,
                    context=context,
                ))
                repo_hits += 1

        print(f"  {repo:45} {commit}  hits={repo_hits}")

    print(f"\nScanned {files_scanned:,} files ({bytes_scanned/1e6:.1f} MB), {len(hits)} hits")
    return hits


def write_hits(hits: list[Hit], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps([asdict(h) for h in hits], indent=2) + "\n")
    print(f"Wrote {len(hits)} hits to {out_path} — adjudicate each `verdict` field.")


def report(hits_path: Path) -> None:
    """
    Summarise adjudicated results.

    Refuses to compute precision while any hit is UNREVIEWED: a number derived
    from unlabelled hits would be exactly the kind of unearned figure this whole
    exercise exists to avoid.
    """
    data = json.loads(hits_path.read_text())
    total = len(data)
    unreviewed = [h for h in data if h["verdict"] == "UNREVIEWED"]
    tps = [h for h in data if h["verdict"] == "TRUE_POSITIVE"]
    fps = [h for h in data if h["verdict"] == "FALSE_POSITIVE"]

    print(f"Total hits     : {total}")
    print(f"True positives : {len(tps)}")
    print(f"False positives: {len(fps)}")
    print(f"Unreviewed     : {len(unreviewed)}")

    if unreviewed:
        print("\nPrecision NOT reported — adjudication incomplete.")
        print("Every hit must be labelled TRUE_POSITIVE or FALSE_POSITIVE first.")
        return

    if total == 0:
        print("\nNo hits across the corpus. Report as an upper bound on FP rate,")
        print("not as precision — precision is undefined with no positives.")
        return

    print(f"\nPrecision-in-the-wild: {len(tps) / total:.3f}")

    by_type: dict[str, list[int]] = {}
    for h in data:
        entry = by_type.setdefault(h["credential_type"], [0, 0])
        entry[0 if h["verdict"] == "TRUE_POSITIVE" else 1] += 1
    print("\nBy credential type (TP / FP):")
    for ctype, (tp, fp) in sorted(by_type.items()):
        print(f"  {ctype:28} {tp:4} / {fp:<4}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone", action="store_true", help="Shallow-clone the corpus.")
    parser.add_argument("--scan", action="store_true", help="Scan and emit hits for review.")
    parser.add_argument("--report", action="store_true", help="Summarise adjudicated hits.")
    parser.add_argument("--out", default="data/fp_corpus_hits.json")
    args = parser.parse_args()

    out_path = Path(args.out)

    if args.clone:
        clone_corpus()
    if args.scan:
        write_hits(scan_corpus(), out_path)
    if args.report:
        report(out_path)
    if not (args.clone or args.scan or args.report):
        parser.print_help()


if __name__ == "__main__":
    main()
