"""``afp graph`` commands."""

from attack_pivot.db import connect
from attack_pivot.graph import sync as graph_sync


def register(subparsers):
    parser = subparsers.add_parser("graph", help="AGE graph materialization")
    sub = parser.add_subparsers(dest="graph_command", required=True, metavar="<action>")
    sync = sub.add_parser("sync", help="Rebuild the graph from the relational tables")
    sync.add_argument(
        "--attack-version", help="ATT&CK version (default: latest synced)"
    )
    sync.add_argument(
        "--run",
        help="model run (id, prefix or label) for NEXT edges; default: the active run",
    )
    sync.set_defaults(command=_sync)


def _sync(args):
    with connect(args.database_url) as conn:
        counts = graph_sync.sync(conn, args.attack_version, args.run)
    print("graph synced: " + ", ".join(f"{n} {k}" for k, n in counts.items() if n))
