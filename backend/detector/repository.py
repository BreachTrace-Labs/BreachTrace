"""Bounded whole-codebase scan. Reads files only; never imports repository code."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time

from detector.scanner import scan_text


@dataclass(frozen=True)
class ScanLimits:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_files: int = 100_000
    max_findings: int = 10_000
    timeout_s: float = 180


# Only administrative/generated/dependency directories. Hidden source and .env
# files are scanned. Exclusions are always disclosed in the report.
EXCLUDED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next"}


def scan_repository(root: str | Path, limits: ScanLimits | None = None) -> dict:
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository root must be a directory")
    limits = limits or ScanLimits()
    if min(limits.max_file_bytes, limits.max_total_bytes, limits.max_files, limits.max_findings, limits.timeout_s) <= 0:
        raise ValueError("Scan limits must be positive")
    started = time.perf_counter()
    result = {"files_scanned": 0, "bytes_scanned": 0, "files_seen": 0, "findings": [],
              "skipped": {}, "excluded_directories": sorted(EXCLUDED_DIRS),
              "complete": True, "stopped_reason": None}
    skips = Counter()

    def stop(reason):
        result["complete"] = False
        result["stopped_reason"] = reason

    def walk_error(_error):
        skips["unreadable_directory"] += 1
        result["complete"] = False

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        kept = []
        for name in sorted(dirs):
            path = Path(directory) / name
            if name in EXCLUDED_DIRS:
                skips["excluded_directory"] += 1
            elif path.is_symlink():
                skips["symlink_directory"] += 1
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            if time.perf_counter() - started >= limits.timeout_s:
                stop("timeout"); break
            if result["files_seen"] >= limits.max_files:
                stop("file_limit"); break
            result["files_seen"] += 1
            path = Path(directory) / name
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    skips["symlink_or_special_file"] += 1; continue
                if info.st_size > limits.max_file_bytes:
                    skips["oversized_file"] += 1; continue
                if result["bytes_scanned"] + info.st_size > limits.max_total_bytes:
                    stop("byte_limit"); break
                # O_NOFOLLOW closes the final-component symlink race. A second
                # fstat also rejects replacement with a pipe/device before read.
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        skips["symlink_or_special_file"] += 1; continue
                    data = stream.read(limits.max_file_bytes + 1)
                if len(data) > limits.max_file_bytes:
                    skips["oversized_file"] += 1; continue
                if result["bytes_scanned"] + len(data) > limits.max_total_bytes:
                    stop("byte_limit"); break
                if b"\x00" in data:
                    skips["binary_file"] += 1; continue
                try:
                    text = data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    skips["non_utf8_file"] += 1; continue
            except OSError:
                skips["unreadable_file"] += 1
                result["complete"] = False
                continue
            result["files_scanned"] += 1
            result["bytes_scanned"] += len(data)
            relative = path.relative_to(root).as_posix()
            diagnostics: list[str] = []
            file_matches = scan_text(text, diagnostics=diagnostics)
            for reason in set(diagnostics):
                skips[reason] += 1
                result["complete"] = False
            for match in file_matches:
                if len(result["findings"]) >= limits.max_findings:
                    stop("finding_limit"); break
                identity = f"{relative}:{match.line_number}:{match.credential_type}:{match.credential_hint}"
                result["findings"].append({"path": relative, "line_number": match.line_number,
                                           "credential_type": match.credential_type,
                                           "credential_hint": match.credential_hint,
                                           "fingerprint": hashlib.sha256(identity.encode()).hexdigest(),
                                           "detection_method": getattr(match, "detection_method", None) or "plaintext",
                                           "confidence": getattr(match, "confidence", None),
                                           "line_end": getattr(match, "line_end", None) or match.line_number,
                                           "validity": "not-verified"})
            # The final file can consume the remaining budget. Do not call the
            # result complete just because there is no next file to check.
            if not result["stopped_reason"] and time.perf_counter() - started >= limits.timeout_s:
                stop("timeout")
            if result["stopped_reason"]:
                break
        if result["stopped_reason"]:
            break
    result["skipped"] = dict(skips)
    result["duration_s"] = round(time.perf_counter() - started, 6)
    result["finding_count"] = len(result["findings"])
    # complete means traversal finished under this disclosed policy, not that
    # binary/excluded/oversized files or git history were scanned.
    result["coverage"] = "current UTF-8 text files within listed exclusions and limits; not git history"
    return result
