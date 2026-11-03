"""``afp review``."""

import json

from attack_pivot.db import connect
from attack_pivot.review import queue


def register(subparsers):
    parser = subparsers.add_parser("review", help="Human review of extracted flows")
    sub = parser.add_subparsers(
        dest="review_command", required=True, metavar="<action>"
    )

    sample = sub.add_parser(
        "sample", help="Sample unreviewed LLM flows into a review batch"
    )
    sample.add_argument("--batch", required=True)
    sample.add_argument("--fraction", type=float, default=0.10)
    sample.add_argument("--max", type=int, default=50, dest="cap")
    sample.add_argument("--seed", type=int, default=0)
    sample.set_defaults(command=_sample)

    ls = sub.add_parser("list", help="Flows in a batch waiting for review")
    ls.add_argument("--batch", required=True)
    ls.set_defaults(command=_list)

    show = sub.add_parser(
        "show", help="A flow's edges with order_basis and evidence quote"
    )
    show.add_argument("flow")
    show.set_defaults(command=_show)

    accept = sub.add_parser("accept", help="Every edge of the flow is correct")
    accept.add_argument("flow")
    accept.add_argument("--by", required=True)
    accept.set_defaults(command=_accept)

    correct = sub.add_parser("correct", help="Fix edges; the rest count as correct")
    correct.add_argument("flow")
    correct.add_argument("--by", required=True)
    correct.add_argument(
        "--flip", action="append", default=[], metavar="EDGE", help="Reverse an edge"
    )
    correct.add_argument(
        "--delete",
        action="append",
        default=[],
        metavar="EDGE",
        help="Remove a spurious edge",
    )
    correct.add_argument(
        "--basis",
        action="append",
        default=[],
        metavar="EDGE=BASIS",
        help="Change order_basis",
    )
    correct.add_argument(
        "--add",
        action="append",
        default=[],
        metavar="SRC:DST:BASIS",
        help="Add a missed edge (action node refs)",
    )
    correct.set_defaults(command=_correct)

    reject = sub.add_parser("reject", help="The flow is unusable")
    reject.add_argument("flow")
    reject.add_argument("--by", required=True)
    reject.set_defaults(command=_reject)

    report = sub.add_parser("report", help="Edge precision against PRD §5.4")
    report.add_argument("--batch")
    report.set_defaults(command=_report)


def _sample(args):
    with connect(args.database_url) as conn:
        ids = queue.sample(conn, args.batch, args.fraction, args.cap, args.seed)
    print(f"batch {args.batch!r}: {len(ids)} flows")


def _list(args):
    with connect(args.database_url) as conn:
        rows = queue.pending(conn, args.batch)
    for r in rows:
        print(
            f"{r['id']}  {r['edges']:>3} edges  {r['source_class'] or '-':<12} {r['name']}"
        )
    print(f"{len(rows)} waiting")


def _show(args):
    with connect(args.database_url) as conn:
        flow, edges = queue.show(conn, args.flow)
    print(
        f"{flow['id']}  [{flow['review_status']}]  {flow['name']}\n{flow['url'] or ''}"
    )
    for e in edges:
        quote = f'  "{e["evidence_quote"]}"' if e["evidence_quote"] else ""
        print(
            f"{e['id'][:8]}  {e['src_technique'] or '?'} -> {e['dst_technique'] or '?'}  "
            f"{e['order_basis']}/{e['via']}  ({e['src_name']} -> {e['dst_name']}){quote}"
        )


def _accept(args):
    with connect(args.database_url) as conn:
        queue.accept(conn, args.flow, args.by)
    print("accepted")


def _correct(args):
    basis = dict(item.split("=", 1) for item in args.basis)
    add = []
    for item in args.add:
        parts = item.split(":")
        if len(parts) != 3:
            raise RuntimeError(f"--add expects SRC:DST:BASIS, got {item!r}")
        add.append(tuple(parts))
    with connect(args.database_url) as conn:
        queue.correct(conn, args.flow, args.by, args.flip, args.delete, basis, add)
    print("corrected")


def _reject(args):
    with connect(args.database_url) as conn:
        queue.reject(conn, args.flow, args.by)
    print("rejected")


def _report(args):
    with connect(args.database_url) as conn:
        result = queue.report(conn, args.batch)
    print(json.dumps(result, indent=2))
    return 0 if result["passes"] else 2
