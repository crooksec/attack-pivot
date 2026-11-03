"""``afp attack`` commands."""

from attack_pivot.db import connect
from attack_pivot.normalize import attack

DEFAULT_VERSION = "20.0"


def register(subparsers):
    parser = subparsers.add_parser("attack", help="ATT&CK reference data")
    sub = parser.add_subparsers(
        dest="attack_command", required=True, metavar="<action>"
    )
    sync = sub.add_parser(
        "sync", help="Load an ATT&CK Enterprise release into the database"
    )
    sync.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help=f"ATT&CK version (default: {DEFAULT_VERSION})",
    )
    sync.set_defaults(command=_sync)


def _sync(args):
    bundle = attack.fetch_bundle(args.version)
    data = attack.parse_bundle(bundle, args.version)
    with connect(args.database_url) as conn:
        counts = attack.load(conn, data, attack.STIX_URL.format(version=args.version))
    print(f"ATT&CK {args.version}: " + ", ".join(f"{n} {k}" for k, n in counts.items()))
