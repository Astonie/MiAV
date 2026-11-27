import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from agent.core.scanner import ScanOptions, scan


def test_file_scan_metadata_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_bytes(b"hello")
    report = scan(path)
    assert report.status == "completed"
    assert report.clean_files == 1
    info = report.results[0].file
    assert info["path"] == str(path)
    assert info["size"] == 5
    assert info["mime_type"] == "text/plain"
    assert info["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert info["modified_at"]


def test_recursive_empty_and_unknown(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "sample.bin").write_bytes(b"\x00\xff")
    assert scan(tmp_path).total_files_discovered == 0
    report = scan(tmp_path, ScanOptions(recursive=True))
    assert report.total_files_discovered == 1
    assert report.unknown_files == 1
    assert report.results[0].classification == "UNKNOWN"


def test_cli_json_and_report_output(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("hello")
    output = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent",
            "scan",
            str(target),
            "--format",
            "json",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == json.loads(output.read_text())
    assert json.loads(result.stdout)["clean_files"] == 1
    assert '"event": "scan_started"' in result.stderr
    if os.name != "nt":
        assert output.stat().st_mode & 0o077 == 0


def test_cli_errors_and_unknown_exit(tmp_path: Path) -> None:
    target = tmp_path / "unknown"
    target.write_bytes(b"\x00\xff")
    result = subprocess.run(
        [sys.executable, "-m", "agent", "scan", str(target), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["unknown_files"] == 1
    missing = scan(tmp_path / "missing")
    assert missing.status == "error"
    assert missing.issues


def test_suspicious_corrupt_executable_and_progress(tmp_path: Path) -> None:
    target = tmp_path / "fake.txt"
    target.write_bytes(b"MZ" + bytes(62))
    progress: list[int] = []
    report = scan(target, progress=progress.append)
    assert progress == [1]
    assert report.suspicious_files == 1
    assert {item.indicator for item in report.results[0].detections} == {
        "MALFORMED_PE_HEADER",
        "EXECUTABLE_EXTENSION_MISMATCH",
    }


def test_entry_limit_is_partial(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    report = scan(tmp_path, ScanOptions(max_entries=1))
    assert report.status == "partial"
    assert report.total_files_discovered == 1
    assert report.issues[0]["error"] == "Maximum directory entry count reached"


def test_directory_depth_limit_is_partial(tmp_path: Path) -> None:
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "file").write_text("outside depth limit")
    report = scan(tmp_path, ScanOptions(recursive=True, max_depth=0))
    assert report.status == "partial"
    assert report.files_successfully_scanned == 0
    assert report.issues[0]["path"] == str(tmp_path / "child")
    assert report.issues[0]["error"] == "Maximum directory depth reached"


def test_invalid_path_is_reported() -> None:
    report = scan("/invalid\0path")
    assert report.status == "error"
    assert report.issues
