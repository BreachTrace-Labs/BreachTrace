from pathlib import Path
import time

from detector.repository import ScanLimits, scan_repository
from detector.scanner import scan_text


KEY = "gsk_" + ("Q7vNm2Lp9Rt4Xs6Hd8Jk3Bc5Wz1Fg0EaU" * 2)[:52]


def test_whole_file_scanning_does_not_interpret_source_as_diff():
    for prefix in ("-", "+", "+++", "---", "diff --git "):
        assert scan_text(prefix + 'GROQ_API_KEY="' + KEY + '"')


def test_scan_masks_findings_and_skips_links_binary_and_dependencies(tmp_path):
    (tmp_path / ".env").write_text("GROQ_API_KEY=" + KEY)
    (tmp_path / "binary").write_bytes(b"\x00" + KEY.encode())
    (tmp_path / "link").symlink_to(tmp_path / ".env")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "key").write_text(KEY)
    result = scan_repository(tmp_path)
    assert result["finding_count"] == 1
    assert result["findings"][0]["path"] == ".env"
    assert KEY not in str(result)
    assert result["skipped"]["binary_file"] == 1
    assert result["skipped"]["symlink_or_special_file"] == 1
    assert result["skipped"]["excluded_directory"] == 1


def test_limits_are_visible_and_large_files_do_not_crash(tmp_path):
    (tmp_path / "big").write_text("a" * 100)
    result = scan_repository(tmp_path, ScanLimits(max_file_bytes=10))
    assert result["skipped"]["oversized_file"] == 1
    for name in ("a", "b"):
        (tmp_path / name).write_text(KEY)
    limited = scan_repository(tmp_path, ScanLimits(max_files=1))
    assert not limited["complete"] and limited["stopped_reason"] == "file_limit"
    assert limited["files_seen"] == 1


def test_long_tokens_do_not_cause_quadratic_email_matching():
    from detector.patterns import find_gcp_credentials
    start = time.perf_counter()
    assert find_gcp_credentials("a" * 200_000 + "@invalid.iam.gserviceaccount.com") == []
    assert time.perf_counter() - start < 2


def test_timeout_in_final_file_is_reported_and_keeps_findings(tmp_path, monkeypatch):
    from detector import repository
    (tmp_path / "one.env").write_text("GROQ_API_KEY=" + KEY)
    clock = [0.0]
    monkeypatch.setattr(repository.time, "perf_counter", lambda: clock[0])
    original = repository.scan_text

    def scan_after_budget(*args, **kwargs):
        result = original(*args, **kwargs)
        clock[0] = 2.0
        return result

    monkeypatch.setattr(repository, "scan_text", scan_after_budget)
    result = scan_repository(tmp_path, ScanLimits(timeout_s=1))
    assert not result["complete"] and result["stopped_reason"] == "timeout"
    assert result["finding_count"] == 1 and KEY not in str(result)
