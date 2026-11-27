"""Windows tests for the current unsupported-platform security boundary."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent.core.scanner import scan

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")


@pytest.mark.parametrize("target", [r"\\server\share\file", r"C:\file:alternate"])
def test_windows_network_and_alternate_streams_fail_closed(target: str) -> None:
    report = scan(target)
    assert report.status == "error"
    assert "unsupported" in report.issues[0]["error"]
    assert report.results == []
    assert report.clean_files == 0


def test_windows_local_file_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "local.txt"
    path.write_text("untouched")

    def unexpected_open(*args: object, **kwargs: object) -> int:
        raise AssertionError("Windows scanning must not open the target")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", unexpected_open)
        report = scan(path)
    assert report.status == "error"
    assert "unsupported" in report.issues[0]["error"]
    assert report.results == []
    assert path.read_text() == "untouched"


def test_windows_cli_reports_failure_and_does_not_create_report(tmp_path: Path) -> None:
    target = tmp_path / "local.txt"
    target.write_text("untouched")
    output = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "-m", "agent", "scan", str(target), "--format", "json"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "error"
    result = subprocess.run(
        [sys.executable, "-m", "agent", "scan", str(target), "--output", str(output)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not output.exists()
