"""Sequential scan orchestration with descriptor-relative, no-follow access."""

import json
import logging
import os
import stat
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent.core.file_processor import FileTooLarge, ScanCancelled, process_file
from agent.detection.classifier import classify
from agent.detection.models import DetectionResult, ScanReport
from engine.heuristics.analyzer import analyze

LOGGER = logging.getLogger("miav.scan")


class ScanLimitReached(Exception):
    """The configured traversal limit was reached."""


def _event(event: str, **fields: object) -> None:
    LOGGER.info(json.dumps({"event": event, **fields}))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _require_safe_access() -> None:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
    ):
        raise OSError(
            "Safe descriptor-relative scanning is unsupported on this platform"
        )


def open_parent(path: Path) -> tuple[int, str]:
    """Open each parent without following links; caller must close the descriptor."""
    _require_safe_access()
    parts = path.parts
    if not path.is_absolute():
        raise ValueError("absolute path required")
    if ".." in parts:
        raise ValueError("parent path components are not permitted")
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        return fd, parts[-1] if len(parts) > 1 else "."
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True)
class ScanOptions:
    recursive: bool = False
    chunk_size: int = 1024 * 1024
    max_file_size: int = 256 * 1024 * 1024
    suspicious_threshold: int = 1
    max_entries: int = 100_000

    def __post_init__(self) -> None:
        if not 1 <= self.chunk_size <= 16 * 1024 * 1024:
            raise ValueError("chunk size must be between 1 byte and 16 MiB")
        if self.max_file_size < 1:
            raise ValueError("maximum file size must be positive")
        if self.suspicious_threshold < 1:
            raise ValueError("suspicious threshold must be positive")
        if self.max_entries < 1:
            raise ValueError("maximum entry count must be positive")


def scan(
    target: str | Path,
    options: ScanOptions = ScanOptions(),
    *,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int], None] = lambda count: None,
) -> ScanReport:
    """Scan a file or directory; report partial results and failures explicitly."""
    path = Path(os.path.abspath(target))
    report = ScanReport(str(uuid.uuid4()), _now(), str(path))
    start = time.monotonic()
    seen: set[tuple[int, int]] = set()
    entries_seen = 0
    _event("scan_started", scan_id=report.scan_id)

    def issue(message: str, location: Path = path) -> None:
        report.issues.append({"path": str(location), "error": message})
        _event("scan_error", scan_id=report.scan_id, error=message)

    def add_result(result: DetectionResult) -> None:
        report.results.append(result)
        if result.scan_status == "completed":
            report.files_successfully_scanned += 1
            if result.classification == "CLEAN":
                report.clean_files += 1
            elif result.classification == "SUSPICIOUS":
                report.suspicious_files += 1
            elif result.classification == "MALICIOUS":
                report.malicious_files += 1
            else:
                report.unknown_files += 1
        elif result.scan_status == "skipped":
            report.files_skipped += 1
        else:
            report.files_with_errors += 1
        _event(
            "file_classified",
            scan_id=report.scan_id,
            classification=result.classification,
            indicators=[finding.indicator for finding in result.detections],
        )
        progress(report.total_files_discovered)

    def file_scan(
        parent: int, name: str, display: Path, initial: os.stat_result
    ) -> None:
        report.total_files_discovered += 1
        metadata: dict[str, object] = {
            "name": name,
            "path": str(display),
            "extension": display.suffix.lower(),
            "size": initial.st_size,
            "sha256": None,
            "mime_type": None,
            "format": None,
            "created_at": None,
            "modified_at": None,
        }
        result = DetectionResult(
            report.scan_id, metadata, "ERROR", 0, [], "error", _now()
        )
        key = (initial.st_dev, initial.st_ino)
        if key in seen:
            result.classification, result.scan_status, result.error = (
                "UNKNOWN",
                "skipped",
                "Duplicate file identity",
            )
            add_result(result)
            return
        seen.add(key)
        if initial.st_size > options.max_file_size:
            result.classification, result.scan_status, result.error = (
                "UNKNOWN",
                "skipped",
                "File exceeds configured size limit",
            )
            add_result(result)
            return
        fd = -1
        try:
            metadata["modified_at"] = datetime.fromtimestamp(
                initial.st_mtime, timezone.utc
            ).isoformat()
            birth = getattr(initial, "st_birthtime", None)
            if birth is not None:
                metadata["created_at"] = datetime.fromtimestamp(
                    birth, timezone.utc
                ).isoformat()
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent,
            )
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or _identity(initial) != _identity(
                opened
            ):
                raise OSError("File changed before scanning")
            data = process_file(
                fd,
                chunk_size=options.chunk_size,
                max_size=options.max_file_size,
                cancelled=cancelled,
            )
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(opened) != _identity(after) or _identity(after) != _identity(
                current
            ):
                raise OSError("File changed during scanning")
            kind, mime, value, findings = analyze(
                data.header, display.suffix, data.counts, data.size, data.strings
            )
            if kind is None and data.is_text:
                kind, mime = "text", "text/plain"
            metadata.update(
                sha256=data.sha256, format=kind, mime_type=mime, entropy=value
            )
            result.classification = classify(
                findings,
                assessed=kind is not None,
                threshold=options.suspicious_threshold,
            )
            result.risk_score = sum(f.score for f in findings)
            result.detections = findings
            result.scan_status = "completed"
        except ScanCancelled:
            result.classification, result.scan_status, result.error = (
                "UNKNOWN",
                "skipped",
                "Scan cancelled",
            )
            add_result(result)
            raise
        except FileTooLarge:
            result.classification, result.scan_status, result.error = (
                "UNKNOWN",
                "skipped",
                "File exceeded configured size limit during scanning",
            )
        except OSError as exc:
            result.error = f"{type(exc).__name__}: {exc.strerror or str(exc)}"
            _event("file_error", scan_id=report.scan_id, error=result.error)
        except (OverflowError, ValueError) as exc:
            result.error = f"Invalid file metadata: {exc}"
            _event("file_error", scan_id=report.scan_id, error=result.error)
        finally:
            if fd >= 0:
                os.close(fd)
        add_result(result)

    def walk(directory_fd: int, display: Path) -> None:
        nonlocal entries_seen
        if cancelled():
            raise ScanCancelled()
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if cancelled():
                        raise ScanCancelled()
                    if entries_seen >= options.max_entries:
                        issue("Maximum directory entry count reached", display)
                        raise ScanLimitReached()
                    entries_seen += 1
                    child = display / entry.name
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode):
                            file_scan(directory_fd, entry.name, child, info)
                        elif stat.S_ISDIR(info.st_mode) and options.recursive:
                            child_fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory_fd,
                            )
                            try:
                                opened = os.fstat(child_fd)
                                if (info.st_dev, info.st_ino) != (
                                    opened.st_dev,
                                    opened.st_ino,
                                ):
                                    raise OSError("Directory changed before traversal")
                                walk(child_fd, child)
                            finally:
                                os.close(child_fd)
                        elif not stat.S_ISDIR(info.st_mode):
                            report.total_files_discovered += 1
                            report.files_skipped += 1
                            progress(report.total_files_discovered)
                    except OSError as exc:
                        issue(
                            f"Entry could not be processed: {type(exc).__name__}: "
                            f"{exc.strerror or str(exc)}",
                            child,
                        )
        except OSError as exc:
            issue(
                f"Directory could not be read: {type(exc).__name__}: "
                f"{exc.strerror or str(exc)}",
                display,
            )
        except RecursionError:
            issue("Directory nesting exceeds the traversal limit", display)

    try:
        if ".." in Path(target).parts:
            raise OSError("Parent path components are not permitted")
        parent, name = open_parent(path)
        try:
            initial = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISREG(initial.st_mode):
                file_scan(parent, name, path, initial)
            elif stat.S_ISDIR(initial.st_mode):
                root_fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                )
                try:
                    opened_root = os.fstat(root_fd)
                    if (initial.st_dev, initial.st_ino) != (
                        opened_root.st_dev,
                        opened_root.st_ino,
                    ):
                        raise OSError("Directory changed before traversal")
                    walk(root_fd, path)
                finally:
                    os.close(root_fd)
            else:
                issue(
                    "Target is not a regular file or directory (links are not followed)"
                )
        finally:
            os.close(parent)
        report.status = (
            "partial"
            if report.issues or report.files_with_errors or report.files_skipped
            else "completed"
        )
    except ScanCancelled:
        report.status = "cancelled"
    except ScanLimitReached:
        report.status = "partial"
    except (OSError, ValueError) as exc:
        detail = exc.strerror if isinstance(exc, OSError) else None
        issue(
            f"Target could not be scanned: {type(exc).__name__}: {detail or str(exc)}"
        )
        report.status = "error"
    finally:
        report.completed_at = _now()
        report.duration_seconds = round(time.monotonic() - start, 6)
        _event(
            "scan_completed",
            scan_id=report.scan_id,
            status=report.status,
            files=report.files_successfully_scanned,
        )
    return report
