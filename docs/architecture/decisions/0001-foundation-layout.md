# 0001: Foundation layout and packaging

Status: accepted for the initial development foundation.

The top-level `agent` package contains the CLI and platform identification.
Only `agent` is packaged now; other top-level component directories are
reserved for future milestones and are not Python packages or functioning
services. Empty directories use `.gitkeep` so Git preserves the agreed
boundaries. Modules and platform interfaces will be introduced when real
implementations require them, avoiding placeholder protection APIs.

The distribution metadata in `pyproject.toml` is the single source of version
information. The CLI reads installed package metadata; development therefore
uses an editable installation. The same file provides development-tool
configuration. No application runtime configuration loader is required yet;
it will be designed when a real configurable capability exists.
