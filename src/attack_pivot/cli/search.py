"""``afp search``: find report URLs with Serper/Brave, review them, fetch the covered ones."""

from attack_pivot.collect import run
from attack_pivot.db import connect
from attack_pivot.search import discovery
from attack_pivot.settings.redact import install_log_filter


def register(subparsers):
    parser = subparsers.add_parser(
        "search", help="Discover report URLs with a search API (results are queued)"
    )
    sub = parser.add_subparsers(
        dest="search_command", required=True, metavar="<action>"
    )

    find = sub.add_parser("run", help="Run a query and queue the results")
    find.add_argument("query", nargs="+")
    find.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the providers, keys and budget; send nothing",
    )
    find.set_defaults(command=_run)

    ls = sub.add_parser("queue", help="List queued URLs")
    ls.add_argument(
        "--status",
        default="queued",
        choices=["queued", "fetched", "rejected", "failed"],
    )
    ls.add_argument("--limit", type=int, default=50)
    ls.set_defaults(command=_queue)

    map_ = sub.add_parser(
        "map", help="Declare that a domain is covered by a source's licence review"
    )
    map_.add_argument("domain")
    map_.add_argument("source")
    map_.set_defaults(command=_map)

    unmap = sub.add_parser("unmap", help="Remove a domain mapping")
    unmap.add_argument("domain")
    unmap.set_defaults(command=_unmap)

    reject = sub.add_parser("reject", help="Reject a queued URL (id or URL)")
    reject.add_argument("ident")
    reject.set_defaults(command=_reject)

    fetch = sub.add_parser(
        "fetch", help="Fetch queued URLs whose domain maps to an enabled source"
    )
    fetch.add_argument("--limit", type=int)
    fetch.set_defaults(command=_fetch)


def _run(args):
    install_log_filter()
    query = " ".join(args.query)
    with connect(args.database_url) as conn:
        if args.dry_run:
            planned = discovery.plan(conn)
            if not planned:
                print("search is off (search.provider = off)")
            for p in planned:
                key = "key set" if p["has_key"] else "NO KEY"
                print(
                    f"{p['provider']}: {key}, {p['used']}/{p['budget']} queries used this month"
                )
            print(f"would search: {query!r}; nothing sent")
            return
        stats = discovery.search(conn, query)
    print(", ".join(f"{k} {v}" for k, v in sorted(stats.items())) or "nothing happened")


def _queue(args):
    with connect(args.database_url) as conn:
        rows = discovery.queue(conn, args.status, args.limit)
    for r in rows:
        if r["source"] is None:
            where = "unmapped"
        else:
            where = r["source"] if r["source_enabled"] else f"{r['source']} (disabled)"
        print(
            f"{str(r['id'])[:8]}  {r['domain']:<28} {where:<28} {r['title'] or r['url']}"
        )
    print(f"{len(rows)} {args.status}")


def _map(args):
    with connect(args.database_url) as conn:
        domain = discovery.map_domain(conn, args.domain, args.source)
    print(f"{domain} -> {args.source}")


def _unmap(args):
    with connect(args.database_url) as conn:
        removed = discovery.unmap_domain(conn, args.domain)
    print("removed" if removed else "no such mapping")


def _reject(args):
    with connect(args.database_url) as conn:
        done = discovery.reject(conn, args.ident)
    print("rejected" if done else "no queued URL matched")


def _fetch(args):
    with connect(args.database_url) as conn:
        rows = discovery.queue(conn, "queued", 100000)
        sources = {r["source"] for r in rows if r["source"] and r["source_enabled"]}
        if not sources:
            print("nothing to fetch: no queued URL maps to an enabled source")
            return
        client = run.make_client({"collector_config": None})
        try:
            stats = discovery.fetch_queued(conn, client, args.limit)
        finally:
            client.close()
    print(", ".join(f"{k} {v}" for k, v in sorted(stats.items())))
