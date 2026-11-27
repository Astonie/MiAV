import subprocess
import sys
import sysconfig
from importlib.metadata import version
from pathlib import Path


def test_cli_version() -> None:
    executable = Path(sysconfig.get_path("scripts")) / (
        "miav.exe" if sys.platform == "win32" else "miav"
    )
    result = subprocess.run(
        [str(executable), "version"], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == f"MiAV {version('miav')}"


def test_cli_rejects_unimplemented_command() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "agent", "quarantine", "list"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "invalid choice" in result.stderr
