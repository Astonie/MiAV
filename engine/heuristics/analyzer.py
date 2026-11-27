"""Bounded-memory entropy and simple explainable file characteristics."""

import math
from collections import Counter

from agent.detection.models import Finding


def entropy(counts: Counter[int], size: int) -> float:
    """Calculate Shannon entropy from byte frequencies."""
    if not size:
        return 0.0
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def analyze(
    header: bytes, extension: str, counts: Counter[int], size: int, strings: set[str]
) -> tuple[str | None, str | None, float, list[Finding]]:
    """Analyze basic magic bytes and heuristic indicators, not malware signatures."""
    kind: str | None = None
    mime: str | None = None
    findings: list[Finding] = []
    executable = False
    if header.startswith(b"MZ"):
        kind, mime, executable = "MZ executable", "application/x-dosexec", True
        offset = int.from_bytes(header[60:64], "little") if len(header) >= 64 else 0
        invalid = offset < 64 or offset + 4 > size
        if not invalid and offset + 4 <= len(header):
            if header[offset : offset + 4] == b"PE\x00\x00":
                kind, mime = "PE", "application/vnd.microsoft.portable-executable"
            else:
                invalid = True
        if invalid:
            findings.append(
                Finding(
                    "heuristic",
                    "MALFORMED_PE_HEADER",
                    "medium",
                    15,
                    "Executable has an invalid or incomplete DOS header.",
                    "Missing or invalid PE header offset",
                )
            )
    elif header.startswith(b"\x7fELF"):
        kind, mime, executable = "ELF", "application/x-elf", True
        if len(header) < 16 or header[4] not in (1, 2) or header[5] not in (1, 2):
            findings.append(
                Finding(
                    "heuristic",
                    "MALFORMED_ELF_HEADER",
                    "medium",
                    15,
                    "Executable has an invalid or incomplete ELF identification.",
                    "Invalid ELF class or byte order",
                )
            )
    elif header[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        kind, mime, executable = "Mach-O", "application/x-mach-binary", True
    elif header.startswith(b"%PDF-"):
        kind, mime = "PDF", "application/pdf"
    elif header.startswith(b"PK\x03\x04"):
        kind, mime = "ZIP", "application/zip"
    value = entropy(counts, size)
    if executable and extension.lower() in {".txt", ".jpg", ".jpeg", ".png", ".pdf"}:
        findings.append(
            Finding(
                "heuristic",
                "EXECUTABLE_EXTENSION_MISMATCH",
                "medium",
                20,
                "Executable content has a non-executable extension.",
                f"format={kind}, extension={extension.lower()}",
            )
        )
    if executable and size >= 1024 and value >= 7.5:
        findings.append(
            Finding(
                "heuristic",
                "HIGH_EXECUTABLE_ENTROPY",
                "medium",
                15,
                "Executable has high overall byte entropy; packing may be benign.",
                f"entropy={value:.3f} bits/byte",
            )
        )
    for indicator in sorted(strings) if executable else []:
        findings.append(
            Finding(
                "heuristic",
                "SUSPICIOUS_EMBEDDED_STRING",
                "low",
                10,
                "Executable contains a potentially suspicious command string.",
                indicator,
            )
        )
    return kind, mime, value, findings
