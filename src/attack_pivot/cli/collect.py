"""``afp collect``."""

from datetime import date
from pathlib import Path

from attack_pivot.collect import run
from attack_pivot.db import connect


def register(subparsers):
    parser = subparsers.add_parser(
        "collect",
        help="Fetch new reports from enabled (licence-reviewed) sources",
    )
    parser.add_argument(
        "--source", help="One source by name (default: every enabled network source)"
    )
    parser.add_argument(
        "--since",
        type=date.fromisoformat,
        help="Skip items published before YYYY-MM-DD",
    )
    parser.add_argument("--limit", type=int, help="Stop after N new reports per source")
    parser.add_argument(
        "--urls",
        type=Path,
        help="Fetch the URLs in this file (one per line) for --source",
    )
    parser.add_argument(
        "--files",
        type=Path,
        nargs="+",
        help="Import local files (txt/md/html/pdf) for --source",
    )
    parser.add_argument(
        "--tlp", help="TLP for imported files (required for ISAC sources)"
    )
    parser.set_defaults(command=_collect)


def _collect(args):
    if (args.urls or args.files) and not args.source:
        raise RuntimeError("--urls and --files need --source")
    with connect(args.database_url) as conn:
        if args.source:
            sources = [run.get_source(conn, args.source)]
        else:
            sources = run.enabled_collectable(conn)
            if not sources:
                print(
                    "no enabled network sources; review one and run `afp sources enable`"
                )
                return 0
        for source in sources:
            if args.files:
                stats = run.import_files(conn, source, args.files, args.tlp)
            else:
                with run.make_client(source) as client:
                    stats = run.collect_source(
                        conn,
                        source,
                        client,
                        since=args.since,
                        limit=args.limit,
                        items=run.read_url_list(args.urls) if args.urls else None,
                    )
            summary = (
                ", ".join(f"{k}={v}" for k, v in sorted(stats.items())) or "nothing"
            )
            print(f"{source['name']}: {summary}")
