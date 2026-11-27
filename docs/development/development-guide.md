# Development guide

## Setup

Install Python 3.11 or later, pip and Git. From the repository root, create a
virtual environment and install the project and its development tools:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows, create the environment with `py -3 -m venv .venv` and activate it
with `.venv\Scripts\activate` in Command Prompt or
`.venv\Scripts\Activate.ps1` in PowerShell. Use `python` after activation.
The editable install provides the `miav` executable and distribution metadata.
There are no runtime dependencies. Setuptools is the build backend; pytest,
Ruff and mypy are development dependencies. The build backend may be installed
in pip's isolated build environment.

## Verify and format

```sh
miav version
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy agent
```

To format code, run `python -m ruff format .`. The tests load project
configuration from `pyproject.toml`; there is currently no runtime
configuration file or loader. Tests need no administrator privileges or live
malware. Future detection tests should use controlled fixtures such as EICAR.

## Git workflow

Create a focused branch, inspect `git status` before editing, and preserve
other contributors' changes. Run the checks above, review the diff for secrets
and unintended files, and submit a pull request for human review. Do not
commit credentials, private datasets or live malware. Follow the repository's
review and release practices; do not commit or push on another person's behalf
without their instruction.
