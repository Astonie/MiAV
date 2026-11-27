"""Serializable scan result models."""

from dataclasses import asdict, dataclass, field
from typing import Literal

Classification = Literal["CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN", "ERROR"]


@dataclass(frozen=True)
class Finding:
    engine: str
    indicator: str
    severity: str
    score: int
    description: str
    evidence: str


@dataclass
class DetectionResult:
    scan_id: str
    file: dict[str, object]
    classification: Classification
    risk_score: int
    detections: list[Finding]
    scan_status: str
    timestamp: str
    confidence: None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return asdict(self)


@dataclass
class ScanReport:
    scan_id: str
    started_at: str
    scanned_path: str
    completed_at: str = ""
    duration_seconds: float = 0.0
    status: str = "running"
    total_files_discovered: int = 0
    files_successfully_scanned: int = 0
    files_skipped: int = 0
    files_with_errors: int = 0
    clean_files: int = 0
    suspicious_files: int = 0
    malicious_files: int = 0
    unknown_files: int = 0
    results: list[DetectionResult] = field(default_factory=list)
    issues: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return asdict(self)
