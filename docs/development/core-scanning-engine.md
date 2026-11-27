# Core scanning engine

## Status and scope

MiAV provides an experimental, on-demand file scanner, not comprehensive
antivirus protection. It does not execute, modify, delete or quarantine scanned
files. No signatures, YARA, real-time monitoring or malware-confirmation
mechanism is implemented. A `CLEAN` result means only that the limited
configured heuristics did not identify a finding; it is not proof of safety.
Use controlled benign fixtures, not live malware.

## Architecture

The CLI invokes `agent.core.scanner.scan`, which orchestrates sequential
directory traversal and `agent.core.file_processor.process_file`. The processor
reads an already-open descriptor in chunks and calculates SHA-256, byte
frequencies, a bounded header and selected string matches in a single pass.
The SHA-256 result is lowercase hexadecimal. Entropy is Shannon entropy over
the entire file, calculated from byte counts rather than buffering the file.
There is exactly one worker; there is no parallel scanning.

The heuristic analyzer checks PE, ELF and Mach-O magic, simple PE and ELF
header characteristics, selected executable-extension mismatches, high
executable entropy (at least 1024 bytes and 7.5 bits/byte), and a few
command-like embedded strings in executable content. These rules are
illustrative, can produce false positives and are not calibrated malware
detectors. PDF, ZIP and UTF-8 text are recognized superficially; contents are
not parsed or validated. Unknown binary formats are classified `UNKNOWN`.
MIME and format are content-derived best-effort hints, not trusted claims.

Each finding has an engine, indicator, severity, score, description and
evidence. The classifier returns `SUSPICIOUS` when findings meet the configured
score threshold; findings below it are `UNKNOWN`, never `CLEAN`. A file with no
findings is `CLEAN` only when its basic format is recognized, otherwise
`UNKNOWN`. `ERROR` indicates a failed file scan. `MALICIOUS` is reserved for a
future trusted detection engine; this implementation never assigns it.
Confidence is always null and scores are not probabilities.

## CLI

```sh
miav version
miav scan /absolute/path/to/file
miav scan /absolute/path/to/directory --recursive
miav scan /absolute/path/to/directory --recursive --format json
miav scan /absolute/path/to/file --output /absolute/path/to/new-report.json
```

Directory scans examine immediate files unless `--recursive` is supplied.
Progress and JSON-structured lifecycle, classification and error events go to
stderr; `--format json` writes machine-readable JSON to stdout. `--output`
always writes JSON and requires a **new** file in an existing directory; it
never overwrites an existing file or follows symbolic links. Report creation
failure returns an error, and an incomplete output file may remain after a
write failure. Reports contain absolute file paths and may contain sensitive
metadata: protect and share them appropriately.

Defaults are a 1 MiB chunk, 256 MiB maximum file size, 100,000 directory
entries, 128 directory levels, a 3600-second cooperative deadline, suspicious
score threshold 1 and one worker. Override with
`--chunk-size`, `--max-file-size`, `--max-entries`, `--max-depth`,
`--timeout-seconds` and
`--suspicious-threshold`. The entry limit includes directories and links and
marks the report partial if reached. The maximum configurable depth is 128;
depth 0 scans only the root directory's immediate files. Ctrl-C and the deadline
are checked between reads and directory entries; a blocked operating-system
operation may delay them.
The exit code is 0 for a completed scan with only clean results, 1 for
suspicious findings, 2 for failures, skipped or unknown files, and 130 for
cancellation; a timeout returns 2. Findings below the configured threshold
count as unknown.

## Reports and security

Reports contain scan ID, timestamps, elapsed seconds, target, status, counts,
per-file results and traversal issues. Results include metadata, classification,
score, null confidence, findings and status; SHA-256 is present only after a
consistent scan. File creation time is reported only when the operating system
provides a birth time; modification time is UTC. Files exceeding the limit,
duplicate hard links and links are skipped. Directory errors are recorded in
`issues`; their contents cannot be counted. A non-recursive scan does not
enumerate subdirectories. Partial or cancelled scans are explicitly marked.
Skipped links and special filesystem objects now appear in `results` with
`UNKNOWN` classification, `skipped` status and a reason in `error`. This adds
result entries compared with earlier reports; existing fields are unchanged.

On systems with the necessary descriptor-relative APIs, each path component is
opened without following symbolic links, regular files are opened read-only,
and file identity, size and timestamps are checked before and after the read.
All path components, including ancestors of the requested target and output,
must be real directories, not symlinks. Use an actual path rather than a
symlinked alias. Paths containing `..` are rejected rather than normalized.
An attacker with concurrent filesystem write access can still
race directory renames or make modifications that evade metadata comparisons;
these checks are not a filesystem snapshot or a complete defence against
hostile filesystems. Hard links and mount points cannot establish containment of
physical data. Do not scan attacker-controlled trees with elevated privileges.

The current implementation **fails closed on Windows** and any other platform
without the required no-follow and descriptor-relative primitives. A native,
reviewed Windows handle/reparse-point implementation is required before Windows
scanning can be supported. macOS has been tested; Linux has not been validated
in this environment. Results and duplicate-identity tracking are held in memory
for the full report and bounded by the entry limit, which may still allow
substantial memory consumption. Traversal errors, depth limits and oversized files produce partial
reports rather than a protection claim.
See the [platform security guide](../security/platform-filesystem-security.md)
for platform policies and validation status.

## Benchmark

After an editable install, run `python -m scripts.benchmark_scan` from the
repository root for an
untraced throughput scan and a separate `tracemalloc` peak measurement using a
temporary, synthetic 16 MiB file. Results depend on the machine, filesystem
cache and runtime; traced allocations are not total process RSS. This is a
baseline, not a production performance guarantee.
On the current macOS Apple Silicon development environment with Python 3.12,
one warm-cache run measured 45.69 MiB/s and 4.03 MiB peak traced Python
allocations; this is a single local observation, not a performance threshold.
