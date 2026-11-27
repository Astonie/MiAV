# Platform filesystem security

## Support and validation

| Platform | Implementation | Validation |
| --- | --- | --- |
| macOS | POSIX descriptor-relative experimental scanner | Local regression tests; not production-certified |
| Linux | POSIX descriptor-relative experimental scanner | CI configured; not yet executed or locally validated |
| Windows 10/11 | Scanning and report-file creation fail closed; no native adapter | Windows fail-closed tests and CI configured; not yet executed |

CI configuration is not proof of a successful run. The proposed Windows native
design and its blocker are documented in the
[Windows assessment](windows-scanner-assessment.md). No Windows reparse-point
handling, file identity checks, native handle management or native traversal
are implemented or claimed.

## POSIX security boundary

Parent components and discovered entries are opened relative to directory
descriptors without following symbolic links. An opened file is checked for
regular-file type and its device, inode, size, modification and change times
are compared with discovery and again after streaming. The pathname is checked
again after reading. A failed or changed file is not classified clean.
The checks are not a snapshot and cannot rule out every filesystem race,
hostile filesystem behavior, hard-link or mount-point access, or an object
being moved while an open directory descriptor is retained. The scanner
does not enforce a local-only filesystem policy on POSIX. Do not scan
attacker-controlled trees with elevated privileges.

Each skipped symbolic link or special object is recorded as an `UNKNOWN`
result with `scan_status: "skipped"` and a reason in `error`. Root links
are also skipped. A directory not traversed because of a depth limit is
recorded as an issue, and the report is partial. Failed or unsupported scans
are explicitly non-successful.

## Windows network paths and streams

All Windows scans currently fail closed, including UNC paths, mapped drives,
devices and explicit alternate data streams. There is no native adapter that
can assess the unnamed stream or enumerate alternate streams. Future support
must reject network paths and explicit streams by policy until they have been
independently designed and tested. A future unnamed-stream scan must not claim
that alternate streams were inspected.

## Limits and testing

The scanner uses one worker, bounded chunks, file size, entry count and
directory depth. A cooperative deadline and cancellation are checked between
reads and traversal steps; a blocked OS call cannot be interrupted by this
mechanism, so elapsed time is not a hard upper bound. Reports remain in memory
and can be large up to the entry limit.

On Windows 10/11, after the setup in the
[development guide](../development/development-guide.md), run:

```powershell
python -m ruff check .
python -m ruff format --check .
python -m mypy agent engine
python -m pytest -ra tests/unit tests/integration/test_cli.py tests/security/test_windows_fail_closed.py
```

These are **fail-closed tests**, not Windows scanner validation. The full POSIX
scan tests are not selected in the Windows job. A future native adapter must
add and actually run tests for real links, junctions, race replacements, access
failures, long/Unicode paths, cleanup and supported filesystems before Windows
support is enabled.
