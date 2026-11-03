"""``afp`` command line for ATT&CK-pivot."""

import argparse
import logging
import sys


def build_parser():
    """
    Build the ``afp`` argument parser. Command groups register themselves through
    :data:`COMMAND_MODULES`, each exposing ``register(subparsers)``.

    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="afp",
        description="ATT&CK-pivot: technique-transition model and knowledge graph.",
    )
    parser.add_argument(
        "--log-level",
        default="warning",
        choices=["debug", "info", "warning", "error"],
        help="Logging verbosity (default: warning)",
    )
    parser.add_argument("--database-url", help="Overrides PIVOT_DATABASE_URL")
    subparsers = parser.add_subparsers(
        title="commands", dest="group", metavar="<command>"
    )
    for module in COMMAND_MODULES:
        module.register(subparsers)
    return parser


def main(argv=None):
    """Main entry point for the ``afp`` command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s"
    )
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.command(args) or 0
    except RuntimeError as e:
        if args.log_level == "debug":
            raise
        sys.stderr.write(f"error: {e}\n")
        return 1


from attack_pivot.cli import attack, db  # noqa: E402

COMMAND_MODULES = [db, attack]
