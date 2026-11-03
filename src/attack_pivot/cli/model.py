"""``afp model`` commands."""

from attack_pivot.db import connect
from attack_pivot.model import build
from attack_pivot.model.counting import DEFAULT_BASES


def register(subparsers):
    parser = subparsers.add_parser("model", help="Transition model runs")
    sub = parser.add_subparsers(dest="model_command", required=True, metavar="<action>")

    b = sub.add_parser("build", help="Fit a model run on the current corpus")
    b.add_argument(
        "--level", default="technique", choices=["subtechnique", "technique", "tactic"]
    )
    b.add_argument(
        "--alpha", type=float, default=1.0, help="Dirichlet prior strength (default 1)"
    )
    b.add_argument(
        "--bases",
        default=",".join(DEFAULT_BASES),
        help="order_basis values to count (default: %(default)s)",
    )
    b.add_argument("--self-loops", default="keep", choices=["keep", "drop"])
    b.add_argument("--label")
    b.add_argument("--attack-version", help="default: latest synced")
    b.add_argument("--tlp", help="comma list: only flows with these TLP values")
    b.add_argument("--source-class", help="comma list: only these source classes")
    b.add_argument("--from-date")
    b.add_argument("--to-date")
    b.add_argument("--activate", action="store_true", help="make this the active run")
    b.set_defaults(command=_build)

    a = sub.add_parser("activate", help="Make a run the active one")
    a.add_argument("run", help="run id, id prefix or label")
    a.set_defaults(command=_activate)

    ls = sub.add_parser("list", help="List runs")
    ls.set_defaults(command=_list)

    ev = sub.add_parser("eval", help="Evaluate a run against baselines")
    ev.add_argument("run", help="run id, id prefix, label or 'active'")
    ev.add_argument("--seed", type=int, default=0)
    ev.add_argument("--bootstrap", type=int, default=1000)
    ev.set_defaults(command=_eval)


def _csv(value):
    return [v for v in value.split(",") if v] if value else None


def _build(args):
    corpus_filter = {
        k: v
        for k, v in {
            "tlp": _csv(args.tlp),
            "source_class": _csv(args.source_class),
            "from_date": args.from_date,
            "to_date": args.to_date,
        }.items()
        if v
    }
    with connect(args.database_url) as conn:
        run_id, summary = build.build_run(
            conn,
            level=args.level,
            alpha=args.alpha,
            bases=_csv(args.bases),
            self_loops=args.self_loops,
            label=args.label,
            corpus_filter=corpus_filter,
            attack_version=args.attack_version,
            activate=args.activate,
        )
    c = summary["corpus"]
    print(f"run {run_id}{' (active)' if args.activate else ''}")
    print(f"  {summary['estimates']} estimates, sha256 {summary['sha256'][:16]}")
    print(
        f"  {c['incidents']} incidents, {c['incident_level_transitions']:g} ordered transitions, "
        f"{c['unique_transition_pairs']} unique pairs, dates {c['date_range']}"
    )


def _activate(args):
    with connect(args.database_url) as conn:
        run_id = build.resolve_run(conn, args.run)
        build.activate(conn, run_id)
    print(f"active run: {run_id}")


def _list(args):
    with connect(args.database_url) as conn:
        runs = build.list_runs(conn)
    for r in runs:
        print(
            f"{'*' if r['is_active'] else ' '} {r['id']}  {r['level']:<13} α={r['alpha']:<5} "
            f"{r['incidents']:>5} incidents  {r['created_at']:%Y-%m-%d %H:%M}  {r['label'] or ''}"
        )


def _eval(args):
    from attack_pivot.model import evaluate

    with connect(args.database_url) as conn:
        run_id = build.resolve_run(conn, args.run)
        path = evaluate.evaluate_run(
            conn, run_id, seed=args.seed, n_bootstrap=args.bootstrap
        )
    print(f"evaluation report: {path}")
