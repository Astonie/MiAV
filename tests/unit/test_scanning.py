import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path

import pytest

from agent.core.file_processor import process_file
from agent.core.scanner import ScanOptions
from agent.detection.classifier import classify
from agent.detection.models import DetectionResult, Finding
from engine.heuristics.analyzer import analyze, entropy


def test_streaming_hash_and_pattern_across_chunks(tmp_path: Path) -> None:
    path = tmp_path / "sample"
    content = b"MZ" + b"x" * 100 + b"powershell -enc test"
    path.write_bytes(content)
    fd = os.open(path, os.O_RDONLY)
    try:
        result = process_file(fd, chunk_size=7, max_size=1000, cancelled=lambda: False)
    finally:
        os.close(fd)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size == len(content)
    assert "powershell -enc" in result.strings


def test_entropy() -> None:
    assert entropy(Counter(), 0) == 0
    assert math.isclose(entropy(Counter(range(256)), 256), 8)


def test_heuristic_findings_and_no_malicious_classification() -> None:
    header = b"MZ" + bytes(62)
    kind, _, _, findings = analyze(
        header, ".txt", Counter({i: 4 for i in range(256)}), 1024, set()
    )
    assert kind == "MZ executable"
    assert {item.indicator for item in findings} == {
        "MALFORMED_PE_HEADER",
        "EXECUTABLE_EXTENSION_MISMATCH",
        "HIGH_EXECUTABLE_ENTROPY",
    }
    assert classify(findings, assessed=True) == "SUSPICIOUS"
    assert classify(findings, assessed=True, threshold=100) == "UNKNOWN"
    assert classify([], assessed=False) == "UNKNOWN"
    assert classify([], assessed=True) == "CLEAN"


def test_pe_signature_is_verified() -> None:
    header = bytearray(132)
    header[:2] = b"MZ"
    header[60:64] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\x00\x00"
    kind, mime, _, findings = analyze(
        bytes(header), ".exe", Counter(header), 132, set()
    )
    assert kind == "PE"
    assert mime == "application/vnd.microsoft.portable-executable"
    assert not findings


def test_result_serialization() -> None:
    finding = Finding("heuristic", "EXAMPLE", "low", 1, "Example", "evidence")
    result = DetectionResult(
        "id", {"name": "a"}, "SUSPICIOUS", 1, [finding], "completed", "now"
    )
    serialized = json.loads(json.dumps(result.to_dict()))
    assert serialized["confidence"] is None
    assert serialized["detections"][0]["evidence"] == "evidence"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"chunk_size": 0},
        {"max_file_size": 0},
        {"suspicious_threshold": 0},
        {"max_depth": -1},
        {"max_depth": 129},
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": float("nan")},
    ],
)
def test_invalid_options(kwargs: dict[str, int | float]) -> None:
    with pytest.raises(ValueError):
        ScanOptions(**kwargs)
