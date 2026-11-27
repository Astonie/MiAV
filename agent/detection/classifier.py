"""Conservative, detection-engine-independent classification."""

from agent.detection.models import Classification, Finding


def classify(
    findings: list[Finding], *, assessed: bool, threshold: int = 1
) -> Classification:
    """Classify without treating heuristic scores as proof of malware."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if findings:
        return (
            "SUSPICIOUS"
            if sum(item.score for item in findings) >= threshold
            else "UNKNOWN"
        )
    return "CLEAN" if assessed else "UNKNOWN"
