"""``afp sources`` commands."""

from pathlib import Path

from attack_pivot.collect import registry
from attack_pivot.db import connect


def register(subparsers):
    parser = subparsers.add_parser("sources", help="Source registry")
    sub = parser.add_subparsers(
        dest="sources_command", required=True, metavar="<action>"
    )

    load = sub.add_parser("load", help="Load a registry seed file (upsert by name)")
    load.add_argument(
        "path", type=Path, nargs="?", default=Path("docs/pivot/sources.seed.yaml")
    )
    load.set_defaults(command=_load)

    ls = sub.add_parser("list", help="List sources")
    ls.add_argument("--enabled", action="store_true", help="Only enabled sources")
    ls.set_defaults(command=_list)

    enable = sub.add_parser(
        "enable", help="Record a licence/ToS review and enable a source"
    )
    enable.add_argument("name")
    enable.add_argument("--reviewed-by", required=True)
    enable.add_argument(
        "--licence", help="Verified licence (required while the seed says 'verify')"
    )
    enable.set_defaults(command=_enable)

    disable = sub.add_parser("disable", help="Disable a source")
    disable.add_argument("name")
    disable.set_defaults(command=_disable)


def _load(args):
    rows = registry.read_seed(args.path)
    with connect(args.database_url) as conn:
        result = registry.load(conn, rows)
    print(
        f"sources: {result['inserted']} inserted, {result['updated']} updated"
        + (
            f"; not in seed: {', '.join(result['not_in_seed'])}"
            if result["not_in_seed"]
            else ""
        )
    )


def _list(args):
    with connect(args.database_url) as conn:
        rows = registry.list_sources(conn, True if args.enabled else None)
    for r in rows:
        flag = "on " if r["enabled"] else "off"
        print(f"{flag} {r['source_class']:<18} {r['collector']:<11} {r['name']}")
    print(f"{len(rows)} sources, {sum(r['enabled'] for r in rows)} enabled")


def _enable(args):
    with connect(args.database_url) as conn:
        registry.enable(conn, args.name, args.reviewed_by, args.licence)
    print(f"enabled {args.name!r} (reviewed by {args.reviewed_by})")


def _disable(args):
    with connect(args.database_url) as conn:
        registry.disable(conn, args.name)
    print(f"disabled {args.name!r}")
