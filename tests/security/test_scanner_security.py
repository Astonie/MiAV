import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent.core.scanner as scanner
from agent.core.scanner import ScanOptions, scan


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    (external / "outside.txt").write_text("outside")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(external, target_is_directory=True)
    report = scan(root, ScanOptions(recursive=True))
    assert report.status == "partial"
    assert report.files_skipped == 1
    assert report.files_successfully_scanned == 0
    assert report.results[0].file["path"] == str(root / "link")
    assert report.results[0].classification == "UNKNOWN"
    assert report.results[0].scan_status == "skipped"
    assert "Symbolic link" in str(report.results[0].error)
    assert scan(root / "link").results[0].classification == "UNKNOWN"
    assert scan(root / "link" / "outside.txt").status == "error"


def test_special_object_is_reported_without_opening(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    report = scan(tmp_path)
    assert report.status == "partial"
    assert report.results[0].classification == "UNKNOWN"
    assert report.results[0].error == "Unsupported filesystem object"


def test_directory_replaced_by_link_is_not_traversed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("outside")
    original_open = os.open
    original_parent = scanner.open_parent
    opened: list[str] = []

    def open_parent_and_install_hook(path: Path) -> tuple[int, str]:
        parent, name = original_parent(path)

        def guarded_open(
            name: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
        ) -> int:
            opened.append(name)
            if name == "child":
                child.rename(tmp_path / "moved")
                child.symlink_to(outside, target_is_directory=True)
            return original_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", guarded_open)
        return parent, name

    monkeypatch.setattr(scanner, "open_parent", open_parent_and_install_hook)
    report = scan(root, ScanOptions(recursive=True))
    assert report.status == "partial"
    assert report.files_successfully_scanned == 0
    assert report.issues[0]["path"] == str(child)
    assert "secret" not in opened
    assert (outside / "secret").read_text() == "outside"


def test_hardlink_deduplication_and_size_limit(tmp_path: Path) -> None:
    target = tmp_path / "one"
    target.write_bytes(b"abcd")
    os.link(target, tmp_path / "two")
    report = scan(tmp_path)
    assert report.files_successfully_scanned == 1
    assert report.files_skipped == 1
    assert scan(target, ScanOptions(max_file_size=3)).files_skipped == 1


def test_large_sparse_file_is_skipped_before_read(tmp_path: Path) -> None:
    target = tmp_path / "large"
    try:
        with target.open("wb") as stream:
            stream.truncate(4 * 1024**3)
        result = scan(target)
        assert result.files_skipped == 1
        assert result.results[0].classification == "UNKNOWN"
        assert result.results[0].file["sha256"] is None
    finally:
        target.unlink(missing_ok=True)


def test_disappearing_file_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file"
    target.write_text("hello")
    original = scanner.process_file

    def remove_during_scan(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)  # type: ignore[arg-type]
        target.unlink()
        return result

    monkeypatch.setattr(scanner, "process_file", remove_during_scan)
    report = scan(target)
    assert report.status == "partial"
    assert report.results[0].classification == "ERROR"
    assert report.results[0].file["sha256"] is None


def test_modification_during_scan_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file"
    target.write_text("hello")
    original = scanner.process_file

    def change_during_scan(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)  # type: ignore[arg-type]
        target.write_text("changed")
        return result

    monkeypatch.setattr(scanner, "process_file", change_during_scan)
    result = scan(target).results[0]
    assert result.classification == "ERROR"
    assert result.file["sha256"] is None


def test_cancellation_and_unusual_filename(tmp_path: Path) -> None:
    path = tmp_path / "newline\nname"
    path.write_text("")
    assert scan(path).results[0].classification == "CLEAN"
    report = scan(path, cancelled=lambda: True)
    assert report.status == "cancelled"
    assert report.files_skipped == 1


def test_deadline_during_file_processing_is_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file"
    path.write_text("test data")
    now = [0.0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: now[0])

    def tick() -> bool:
        now[0] += 2
        return False

    report = scan(path, ScanOptions(chunk_size=1, timeout_seconds=1), cancelled=tick)
    assert report.status == "timed_out"
    assert report.results[0].classification == "UNKNOWN"
    assert report.results[0].scan_status == "skipped"
    assert report.results[0].error == "Scan timed out"
    assert report.results[0].file["sha256"] is None


def test_report_never_overwrites_or_follows_links(tmp_path: Path) -> None:
    target = tmp_path / "file"
    target.write_text("original")
    output = tmp_path / "report"
    output.symlink_to(target)
    result = subprocess.run(
        [sys.executable, "-m", "agent", "scan", str(target), "--output", str(output)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert target.read_text() == "original"
    assert "report_write_failed" in result.stderr


def test_report_rejects_symlinked_parent(tmp_path: Path) -> None:
    target = tmp_path / "file"
    target.write_text("original")
    (tmp_path / "alias").symlink_to(tmp_path, target_is_directory=True)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent",
            "scan",
            str(target),
            "--output",
            str(tmp_path / "alias" / "report"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "report").exists()


def test_read_failure_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file"
    target.write_text("hello")

    def denied(*args: object, **kwargs: object) -> None:
        raise PermissionError("access denied")

    monkeypatch.setattr(scanner, "process_file", denied)
    report = scan(target)
    assert report.status == "partial"
    assert report.files_with_errors == 1
    assert "PermissionError" in str(report.results[0].error)


def test_open_file_descriptor_is_closed_after_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file"
    target.write_text("hello")
    opened: list[int] = []

    def failed_read(fd: int, **kwargs: object) -> None:
        opened.append(fd)
        raise PermissionError("access denied")

    monkeypatch.setattr(scanner, "process_file", failed_read)
    assert scan(target).files_with_errors == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_platform_without_safe_access_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file"
    target.write_text("hello")
    monkeypatch.setattr(scanner.os, "supports_fd", set())
    report = scan(target)
    assert report.status == "error"
    assert "unsupported" in report.issues[0]["error"]


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "file"
    target.write_text("hello")
    traversal = str(tmp_path / "child" / ".." / "file")
    report = scan(traversal)
    assert report.status == "error"
    assert "Parent path" in report.issues[0]["error"]
    output = str(tmp_path / "child" / ".." / "report")
    result = subprocess.run(
        [sys.executable, "-m", "agent", "scan", str(target), "--output", output],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "report").exists()
