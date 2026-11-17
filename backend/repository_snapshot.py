"""Download a pinned GitHub snapshot, safely unpack regular files, scan offline."""
from __future__ import annotations

from collections import Counter
import gzip
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

import requests

import config
from detector.repository import EXCLUDED_DIRS, ScanLimits, scan_repository


def repository_name(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or
            parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("Use an HTTPS github.com owner/repository URL")
    name = parsed.path.strip("/").removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", name) or name.split("/")[1] in {".", ".."}:
        raise ValueError("Use a repository root URL, without a branch or file path")
    return name


def unpack(archive: Path, target: Path, limits: ScanLimits) -> dict:
    """Never tar.extract: reject links, devices, traversal and decompression excess."""
    count = total = 0
    skipped = Counter()
    started = time.monotonic()
    prefix = None
    class BoundedReader:
        def __init__(self, source):
            self.source = source
            self.read_bytes = 0

        def read(self, size):
            if time.monotonic() - started > limits.timeout_s:
                raise ValueError("Archive decompression time limit exceeded")
            block = self.source.read(min(size, limits.max_archive_bytes - self.read_bytes + 1))
            self.read_bytes += len(block)
            if self.read_bytes > limits.max_archive_bytes:
                raise ValueError("Archive size limit exceeded")
            return block

    with gzip.open(archive, "rb") as compressed, tarfile.open(fileobj=BoundedReader(compressed), mode="r|") as stream:
        for member in stream:
            count += 1
            if count > limits.max_files or time.monotonic() - started > limits.timeout_s:
                raise ValueError("Snapshot exceeds archive entry/time limits")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or not path.parts:
                raise ValueError("Unsafe archive path")
            if prefix is None:
                prefix = path.parts[0]
            if path.parts[0] != prefix:
                raise ValueError("Unexpected archive root")
            parts = path.parts[1:]
            if not parts or member.isdir():
                continue
            if not member.isfile():
                skipped["links_or_special_files"] += 1; continue
            if any(part in EXCLUDED_DIRS for part in parts[:-1]):
                skipped["excluded_files"] += 1; continue
            if member.size > limits.max_file_bytes:
                skipped["oversized_files"] += 1; continue
            if member.size < 0 or total + member.size > limits.max_total_bytes:
                raise ValueError("Snapshot exceeds expanded byte limit")
            destination = target.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = stream.extractfile(member)
            if source is None:
                raise ValueError("Unreadable archive entry")
            # New directory contains only files we wrote; no links are created.
            with source, destination.open("xb") as output:
                remaining = member.size
                while remaining:
                    block = source.read(min(65536, remaining))
                    if not block:
                        raise ValueError("Truncated archive entry")
                    output.write(block)
                    remaining -= len(block)
            total += member.size
    return {"archive_entries": count, "expanded_bytes": total, "archive_skipped": dict(skipped)}


def scan_github(url: str) -> dict:
    name = repository_name(url)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    def metadata(path):
        response = requests.get("https://api.github.com/repos/" + name + path,
                                headers=headers, timeout=30, allow_redirects=False)
        if response.status_code != 200:
            raise ValueError(f"GitHub request failed (HTTP {response.status_code})")
        return response.json()

    repo = metadata("")
    if repo.get("full_name", "").lower() != name.lower():
        raise ValueError("Repository identity did not match")
    # Pin before downloading; a branch moving mid-download cannot mix revisions.
    from urllib.parse import quote
    commit = metadata("/commits/" + quote(repo["default_branch"], safe=""))["sha"]
    if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
        raise ValueError("Unexpected commit identifier")
    response = requests.get(f"https://api.github.com/repos/{name}/tarball/{commit}",
                            headers=headers, timeout=30, allow_redirects=False, stream=True)
    if response.status_code == 302:
        location = response.headers.get("Location", "")
        parsed = urlsplit(location)
        if parsed.scheme != "https" or parsed.netloc != "codeload.github.com" or parsed.username or parsed.password:
            response.close()
            raise ValueError("Unexpected archive download host")
        response.close()
        # Signed private-archive URL carries its own temporary authorization;
        # never forward the user's GitHub token to a redirected host.
        response = requests.get(location, timeout=30, allow_redirects=False, stream=True)
    if response.status_code != 200:
        response.close()
        raise ValueError("Cannot download repository archive")
    limits = ScanLimits()
    with tempfile.TemporaryDirectory(prefix="breachtrace-snapshot-") as temporary:
        root = Path(temporary)
        archive = root / "snapshot.tar.gz"
        downloaded = 0
        started = time.monotonic()
        with response, archive.open("wb") as output:
            for block in response.iter_content(65536):
                downloaded += len(block)
                if downloaded > limits.max_archive_bytes or time.monotonic() - started > limits.download_timeout_s:
                    raise ValueError("Archive exceeds download size/time limit")
                output.write(block)
        source = root / "source"; source.mkdir()
        archive_info = unpack(archive, source, limits)
        result = scan_repository(source, limits)
        result.update(archive_info)
        result.update({"repo_url": f"https://github.com/{name}", "revision": commit,
                       "branch": repo["default_branch"], "downloaded_bytes": downloaded,
                       "snapshot_only": True,
                       "exposure_start": None,
                       "forensics_started": False})
        return result
