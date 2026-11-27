"""Streaming fingerprinting and bounded-memory byte analysis."""

import codecs
import hashlib
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

PATTERNS = (b"powershell -enc", b"powershell.exe -enc", b"/bin/sh -c")


class ScanCancelled(Exception):
    """The caller requested cancellation."""


class FileTooLarge(Exception):
    """A file exceeded the configured processing limit."""


@dataclass
class ProcessedFile:
    sha256: str
    counts: Counter[int]
    size: int
    header: bytes
    strings: set[str]
    is_text: bool


def process_file(
    fd: int, *, chunk_size: int, max_size: int, cancelled: Callable[[], bool]
) -> ProcessedFile:
    """Hash and inspect an open file in one pass without closing its descriptor."""
    digest = hashlib.sha256()
    counts: Counter[int] = Counter()
    header = b""
    tail = b""
    strings: set[str] = set()
    size = 0
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    is_text = True
    while True:
        if cancelled():
            raise ScanCancelled()
        chunk = os.read(fd, chunk_size)
        if not chunk:
            break
        size += len(chunk)
        if size > max_size:
            raise FileTooLarge()
        digest.update(chunk)
        counts.update(chunk)
        if len(header) < 4096:
            header += chunk[: 4096 - len(header)]
        searchable = (tail + chunk).lower()
        for pattern in PATTERNS:
            if pattern in searchable:
                strings.add(pattern.decode("ascii"))
        tail = searchable[-(max(map(len, PATTERNS)) - 1) :]
        if is_text:
            try:
                decoder.decode(chunk)
                if b"\x00" in chunk:
                    is_text = False
            except UnicodeDecodeError:
                is_text = False
    if is_text:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            is_text = False
    return ProcessedFile(digest.hexdigest(), counts, size, header, strings, is_text)
