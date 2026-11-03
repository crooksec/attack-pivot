"""``afp dedupe``."""

from attack_pivot.db import connect
from attack_pivot.dedupe import run


def register(subparsers):
    parser = subparsers.add_parser(
        "dedupe", help="Cluster flows of the same intrusion into one incident"
    )
    parser.add_argument(
        "--auto-only",
        action="store_true",
        help="Link >= 0.75 only; do not fill the review queue",
    )
    parser.set_defaults(command=_dedupe)
    sub = parser.add_subparsers(dest="dedupe_command", metavar="<action>")

    queue = sub.add_parser("queue", help="List pairs waiting for review")
    queue.add_argument("--limit", type=int, default=20)
    queue.set_defaults(command=_queue)

    resolve = sub.add_parser("resolve", help="Decide a review item")
    resolve.add_argument("id")
    group = resolve.add_mutually_exclusive_group(required=True)
    group.add_argument("--merge", action="store_true")
    group.add_argument("--distinct", action="store_true")
    resolve.add_argument("--by", required=True)
    resolve.set_defaults(command=_resolve)


def _dedupe(args):
    with connect(args.database_url) as conn:
        counts = run.dedupe(conn, args.auto_only)
    print("dedupe: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def _queue(args):
    with connect(args.database_url) as conn:
        items = run.queue(conn, args.limit)
    for i in items:
        s = i["signals"]
        print(
            f"{i['id']} {i['score']:.2f}  {i['label_a']!r} ~ {i['label_b']!r}  "
            f"actor={s['actor']} gap={s['gap_days']} jaccard={s['jaccard']}"
        )
    print(f"{len(items)} open")


def _resolve(args):
    with connect(args.database_url) as conn:
        run.resolve(conn, args.id, args.merge, args.by)
    print("merged" if args.merge else "recorded as distinct")
