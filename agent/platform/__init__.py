"""Cross-platform identification; endpoint protection is not implemented."""

import platform
from typing import Literal

Platform = Literal["windows", "linux", "macos", "unsupported"]


def identify_platform() -> Platform:
    """Identify the operating system without implying protection is available."""
    match platform.system():
        case "Windows":
            return "windows"
        case "Linux":
            return "linux"
        case "Darwin":
            return "macos"
        case _:
            return "unsupported"
