"""Command-line entry point for MiAV."""

import argparse
import json
import logging
import os
import signal
import sys
from importlib.metadata import version
from pathlib import Path

from agent.core.scanner import ScanOptions, open_parent, scan
from agent.detection.models import ScanReport


def _write_report(path: str, payload: str) -> None:
    if ".." in Path(path).parts:
        raise ValueError("parent path components are not permitted")
    parent, name = open_parent(Path(os.path.abspath(path)))
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.write("\n")
    finally:
        os.close(parent)


def _exit_code(report: ScanReport) -> int:
    if report.status == "cancelled":
        return 130
    if report.status != "completed" or report.unknown_files:
        return 2
    if report.suspicious_files or report.malicious_files:
        return 1
    return 0


def main() -> None:
    """Run the version or file scanning command."""
    parser = argparse.ArgumentParser(
        prog="miav", description="MiAV file scanner (not real-time protection)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="show the installed MiAV version")
    scan_parser = commands.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("path")
    scan_parser.add_argument(
        "--recursive", action="store_true", help="include subdirectories"
    )
    scan_parser.add_argument("--format", choices=("text", "json"), default="text")
    scan_parser.add_argument(
        "--output", help="write JSON to a new file; never overwrite"
    )
    scan_parser.add_argument(
        "--chunk-size", type=int, default=1024 * 1024, metavar="BYTES"
    )
    scan_parser.add_argument(
        "--max-file-size", type=int, default=256 * 1024 * 1024, metavar="BYTES"
    )
    scan_parser.add_argument("--suspicious-threshold", type=int, default=1)
    scan_parser.add_argument("--max-entries", type=int, default=100_000)
    args = parser.parse_args()
    if args.command == "version":
        print(f"MiAV {version('miav')}")
        return
    try:
        options = ScanOptions(
            args.recursive,
            args.chunk_size,
            args.max_file_size,
            args.suspicious_threshold,
            args.max_entries,
        )
    except ValueError as exc:
        scan_parser.error(str(exc))
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    interrupted = False

    def interrupt(signum: int, frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    previous = signal.signal(signal.SIGINT, interrupt)
    try:
        report = scan(
            args.path,
            options,
            cancelled=lambda: interrupted,
            progress=lambda count: print(f"Files discovered: {count}", file=sys.stderr),
        )
    finally:
        signal.signal(signal.SIGINT, previous)
    payload = json.dumps(report.to_dict(), ensure_ascii=True, indent=2)
    if args.output:
        try:
            _write_report(args.output, payload)
        except (OSError, ValueError) as exc:
            logging.getLogger("miav.scan").error(
                json.dumps({"event": "report_write_failed", "error": str(exc)})
            )
            raise SystemExit(2) from exc
    if args.format == "json":
        print(payload)
    else:
        print(
            f"Scan {report.status}: {report.files_successfully_scanned} scanned, "
            f"{report.clean_files} clean, {report.suspicious_files} suspicious, "
            f"{report.malicious_files} malicious, {report.unknown_files} unknown, "
            f"{report.files_skipped} skipped, {report.files_with_errors} errors."
        )
        for result in report.results:
            if result.classification != "CLEAN":
                print(f"{result.classification}: {json.dumps(result.file['path'])}")
                for finding in result.detections:
                    print(
                        f"  {finding.indicator}: {finding.description} "
                        f"({finding.evidence})"
                    )
                if result.error:
                    print(f"  {result.error}")
        for issue in report.issues:
            print(f"Error: {issue['error']}", file=sys.stderr)
    raise SystemExit(_exit_code(report))
