# MiAV

MiAV (Mitra Intelligent Antivirus) is an early-stage project by Mitra Systems
Limited to build a cross-platform antivirus and endpoint detection and response
(EDR) platform. Its vision is explainable, resource-conscious protection for
individuals and centrally managed enterprises.

## Status and capabilities

This repository currently provides development infrastructure, a version-only
CLI and basic operating-system identification. **It does not scan or protect
endpoints.** Signature and YARA detection, heuristics, machine learning,
behavioural monitoring, ransomware detection, quarantine, reporting and central
management are planned, not implemented.

Windows 10 and 11 are the initial endpoint targets; Linux and macOS are future
targets. The foundation is intended to be portable, but no operating system
currently has an implemented protection capability.

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
python -m mypy agent
```

See the [development guide](docs/development/development-guide.md) for setup,
testing and Git workflow. Future commands include `miav scan <path>`,
`miav scan <path> --recursive`, `miav quarantine list`, and
`miav report --latest`; these commands are not implemented.

## Contributing

Read [AGENTS.md](AGENTS.md) and the development guide before contributing.
Keep changes focused, include tests and documentation, and submit changes for
human review. Do not commit credentials, private datasets or live malware.
