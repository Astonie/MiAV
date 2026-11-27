# Changelog

## 0.1.0 - Initial Development Foundation (unreleased)

- Added experimental on-demand file and directory scans, streaming SHA-256,
  explainable basic heuristics and JSON reports.
- Added no-follow file access, size limits and cancellation; Windows scanning
  is explicitly unsupported until safe native access is implemented.
- Added project layout, development configuration and engineering documentation.
- Added a version-only CLI and basic platform identification.
- Added initial automated tests; see the development guide for verification commands.

Security: heuristics do not prove files safe or malicious. Real-time monitoring,
signature detection and quarantine are not implemented. No elevated permissions
are required for ordinary scans. See the scanning guide for security limits.
