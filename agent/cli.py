"""Command-line entry point for the MiAV foundation."""

import argparse
from importlib.metadata import version


def main() -> None:
    """Run the currently supported version command."""
    parser = argparse.ArgumentParser(
        prog="miav", description="MiAV development foundation (not endpoint protection)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="show the installed MiAV version")
    args = parser.parse_args()
    if args.command == "version":
        print(f"MiAV {version('miav')}")
