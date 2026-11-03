import base64
import io
from pathlib import Path
import tarfile
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from detector.repository import ScanLimits
from repository_snapshot import repository_name, scan_github, unpack


def make_archive(path, entries):
    with tarfile.open(path, "w:gz") as archive:
        for name, value, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "link":
                info.type = tarfile.SYMTYPE; info.linkname = "/etc/passwd"
                archive.addfile(info)
            else:
                data = value.encode(); info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


@pytest.mark.parametrize("url", ["https://evil.test/github.com/team/repo", "https://github.com.evil.test/a/b", "file:///etc/passwd", "https://github.com/a/../b", "https://github.com/a/b/tree/main", "https://user:pass@github.com/a/b", "https://github.com/a/b?token=secret"])
def test_only_exact_github_repository_roots_allowed(url):
    with pytest.raises(ValueError):
        repository_name(url)


def test_safe_archive_ignores_links_and_records_limits(tmp_path):
    archive = tmp_path / "source.tar.gz"
    make_archive(archive, [("root/code.txt", "content", "file"), ("root/link", "", "link"), ("root/big", "x" * 100, "file")])
    target = tmp_path / "source"; target.mkdir()
    result = unpack(archive, target, ScanLimits(max_file_bytes=10))
    assert (target / "code.txt").read_text() == "content"
    assert not (target / "link").exists() and not (target / "big").exists()
    assert result["archive_skipped"] == {"links_or_special_files": 1, "oversized_files": 1}


def test_archive_rejects_traversal_and_decompression_excess(tmp_path):
    target = tmp_path / "source"; target.mkdir()
    archive = tmp_path / "source.tar.gz"
    make_archive(archive, [("root/../../outside", "evil", "file")])
    with pytest.raises(ValueError, match="Unsafe"):
        unpack(archive, target, ScanLimits())
    make_archive(archive, [("root/large", "a" * 50_000, "file")])
    with pytest.raises(ValueError, match="byte limit"):
        unpack(archive, target, ScanLimits(max_total_bytes=1000))


def test_download_is_pinned_and_redirect_does_not_receive_token(tmp_path, monkeypatch):
    archive = tmp_path / "source.tar.gz"
    value = "gsk_" + ("Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU" * 2)[:52]
    make_archive(archive, [("root/config.env", "GROQ_API_KEY=" + value, "file")])
    meta = Mock(status_code=200); meta.json.return_value = {"full_name": "team/repo", "default_branch": "main"}
    commit = Mock(status_code=200); commit.json.return_value = {"sha": "a" * 40}
    redirect = Mock(status_code=302, headers={"Location": "https://codeload.github.com/team/repo/archive"})
    download = Mock(status_code=200); download.iter_content.return_value = [archive.read_bytes()]
    download.__enter__ = Mock(return_value=download); download.__exit__ = Mock(return_value=False)
    get = Mock(side_effect=[meta, commit, redirect, download])
    monkeypatch.setattr("repository_snapshot.requests.get", get)
    monkeypatch.setattr("repository_snapshot.config.GITHUB_TOKEN", "synthetic-private-token")
    result = scan_github("https://github.com/team/repo")
    assert result["revision"] == "a" * 40 and result["finding_count"] == 1
    assert result["exposure_start"] is None and not result["forensics_started"]
    assert value not in str(result)
    assert get.call_args_list[2].args[0].endswith("a" * 40)
    assert "headers" not in get.call_args_list[3].kwargs


def test_encoded_ai_key_survives_archive_scan_with_masked_provenance(tmp_path, monkeypatch):
    archive = tmp_path / "source.tar.gz"
    value = "sk_" + "Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU"
    encoded = base64.b64encode(value.encode()).decode()
    make_archive(archive, [("root/config.env", f'# synthetic fixture\nSARVAM_API_KEY_B64="{encoded}"\n', "file")])
    meta = Mock(status_code=200)
    meta.json.return_value = {"full_name": "team/repo", "default_branch": "main"}
    commit = Mock(status_code=200)
    commit.json.return_value = {"sha": "a" * 40}
    download = Mock(status_code=200)
    download.iter_content.return_value = [archive.read_bytes()]
    download.__enter__ = Mock(return_value=download)
    download.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("repository_snapshot.requests.get", Mock(side_effect=[meta, commit, download]))
    result = scan_github("https://github.com/team/repo")
    assert result["complete"] and result["finding_count"] == 1
    finding = result["findings"][0]
    assert finding["credential_type"] == "sarvam_api_key"
    assert finding["path"] == "config.env" and finding["line_number"] == 2
    assert "base64" in finding["detection_method"]
    assert finding["validity"] == "not-verified"
    assert value not in str(result) and encoded not in str(result)


def test_scan_api_returns_masked_job_and_preserves_failure_safety(monkeypatch, tmp_path):
    from routers import repositories
    monkeypatch.setattr(repositories, "_jobs", {})
    monkeypatch.setattr(repositories, "scan_github", lambda url: {"finding_count": 0, "findings": [], "repo_url": url})
    # Keep persistence within the test's throwaway directory.
    monkeypatch.setattr(repositories, "__file__", str(tmp_path / "backend" / "routers" / "repositories.py"))
    app = FastAPI(); app.include_router(repositories.router)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 1234)) as client:
        response = client.post("/repositories/scan", json={"repo_url": "https://github.com/team/repo"})
        assert response.status_code == 202
        result = client.get("/repositories/scans/" + response.json()["scan_id"]).json()
        assert result["status"] == "complete" and result["result"]["finding_count"] == 0
        def fail(_url):
            raise ValueError("never expose signed URL or token")
        monkeypatch.setattr(repositories, "scan_github", fail)
        job = client.post("/repositories/scan", json={"repo_url": "https://github.com/team/repo"}).json()
        failed = client.get("/repositories/scans/" + job["scan_id"]).json()
        assert failed["status"] == "failed" and "signed URL" not in str(failed)
        assert client.post("/repositories/scan", json={"repo_url": "https://evil.test/team/repo"}).status_code == 422
