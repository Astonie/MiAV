"""Reproducible, benign local scanner throughput and Python allocation benchmark."""

import json
import os
import tempfile
import time
import tracemalloc
from pathlib import Path

from agent.core.scanner import scan


def main() -> None:
    """Scan 16 MiB of synthetic data, with and without allocation tracing."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(os.path.realpath(directory)) / "benchmark.bin"
        block = bytes(range(256)) * 4096
        with path.open("wb") as stream:
            for _ in range(16):
                stream.write(block)
        start = time.monotonic()
        report = scan(path)
        elapsed = time.monotonic() - start
        if report.status != "completed":
            raise RuntimeError(f"Benchmark scan failed: {report.status}")
        tracemalloc.start()
        try:
            traced_report = scan(path)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        if traced_report.status != "completed":
            raise RuntimeError(f"Traced benchmark scan failed: {traced_report.status}")
        print(
            json.dumps(
                {
                    "bytes": path.stat().st_size,
                    "seconds": round(elapsed, 3),
                    "throughput_mib_per_second": round(16 / elapsed, 2),
                    "traced_peak_mib": round(peak / (1024 * 1024), 2),
                }
            )
        )


if __name__ == "__main__":
    main()
