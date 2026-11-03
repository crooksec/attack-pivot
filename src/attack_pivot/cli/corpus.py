"""``afp corpus``."""

import json

from attack_pivot.corpus import stats
from attack_pivot.db import connect


def register(subparsers):
    parser = subparsers.add_parser("corpus", help="Corpus metrics")
    sub = parser.add_subparsers(
        dest="corpus_command", required=True, metavar="<action>"
    )
    s = sub.add_parser(
        "stats", help="Composition and progress toward M-Proof / M-Stretch"
    )
    s.add_argument("--attack-version", help="ATT&CK version (default: latest synced)")
    s.add_argument("--json", action="store_true", help="Machine-readable output")
    s.set_defaults(command=_stats)


def _stats(args):
    with connect(args.database_url) as conn:
        result = stats.stats(conn, args.attack_version)
    print(
        json.dumps(result, indent=2, default=str) if args.json else stats.render(result)
    )
