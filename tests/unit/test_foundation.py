import importlib
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest

from agent.platform import identify_platform


def test_project_configuration_loads() -> None:
    project_file = Path(__file__).resolve().parents[2] / "pyproject.toml"
    with project_file.open("rb") as stream:
        configuration = tomllib.load(stream)
    assert configuration["project"]["name"] == "miav"
    assert configuration["project"]["version"] == version("miav")


def test_agent_package_imports() -> None:
    assert importlib.import_module("agent").__name__ == "agent"


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("Windows", "windows"),
        ("Linux", "linux"),
        ("Darwin", "macos"),
        ("Other", "unsupported"),
    ],
)
def test_identify_platform(
    monkeypatch: pytest.MonkeyPatch, system: str, expected: str
) -> None:
    monkeypatch.setattr("agent.platform.platform.system", lambda: system)
    assert identify_platform() == expected
