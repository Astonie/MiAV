# MiAV

MiAV (Mitra Intelligent Antivirus) is an early-stage project by Mitra Systems
Limited to build a cross-platform antivirus and endpoint detection and response
(EDR) platform. Its vision is explainable, resource-conscious protection for
individuals and centrally managed enterprises.

## Status and capabilities

This repository provides an experimental on-demand file scanner with streaming
SHA-256, basic explainable heuristics and JSON reports. It does not provide
comprehensive antivirus or real-time endpoint protection. Signature and YARA
detection, machine learning, behavioural monitoring, ransomware detection,
quarantine and central management are planned, not implemented.

Windows 10 and 11 are the initial endpoint targets; Linux and macOS are future
targets. The foundation is intended to be portable, but no operating system
currently has real-time protection. The scanner has been tested on macOS and
fails closed on Windows until safe native file handling is implemented; Linux
has not yet been validated. Windows, Linux and macOS CI is configured but
has not yet run; the Windows job tests fail-closed behavior, not scanning.

## Architecture and technology

The planned architecture separates the endpoint agent, detection engine,
management server and dashboard. Operating-system-specific integrations will
be isolated behind platform interfaces. See the
[system architecture](docs/architecture/system-architecture.md) and
[development roadmap](docs/roadmap/development-roadmap.md).

Python is used for the initial agent; Rust is planned only where performance
justifies it. Future technologies include SHA-256, YARA, LIEF, scikit-learn or
XGBoost, FastAPI, PostgreSQL, Celery, Redis, React and TypeScript. None of these
future frameworks or services are installed as runtime dependencies now.

## Development setup

Prerequisites: Python 3.11 or later, pip, Git and a virtual environment. From
the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
miav version
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy agent engine
```

For example, run `miav scan /path/to/file` or
`miav scan /path/to/directory --recursive --format json`. A `CLEAN` result
only means the limited heuristics found nothing; it does not prove a file safe.
See the [scanning guide](docs/development/core-scanning-engine.md) for options,
exit codes, security boundaries and limitations, and the
[development guide](docs/development/development-guide.md) for setup and
testing. The [platform security guide](docs/security/platform-filesystem-security.md)
describes the Windows blocker and validation status. Quarantine and
`miav report --latest` remain unimplemented.

## Contributing

Read [AGENTS.md](AGENTS.md) and the development guide before contributing.
Keep changes focused, include tests and documentation, and submit changes for
human review. Do not commit credentials, private datasets or live malware.
