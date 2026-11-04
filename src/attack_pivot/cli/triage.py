"""``afp triage``."""

import json
from pathlib import Path

from attack_pivot import llm
from attack_pivot.db import connect
from attack_pivot.ingest.load import latest_attack_version
from attack_pivot.normalize import attack
from attack_pivot.triage import evaluate, run


def register(subparsers):
    parser = subparsers.add_parser(
        "triage", help="Classify collected reports as extraction candidates"
    )
    parser.add_argument("--limit", type=int, help="Triage at most N reports")
    parser.add_argument(
        "--attack-version",
        help="ATT&CK version for counting cited IDs (default: latest)",
    )
    parser.add_argument(
        "--heuristics-only",
        action="store_true",
        help="No LLM calls: cited technique IDs only",
    )
    parser.add_argument(
        "--retriage",
        action="store_true",
        help="Redo reports that already have a decision",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show how many LLM calls and roughly how many tokens a run would use; call no model",
    )
    parser.add_argument("--provider", help="Provider id from the API's providers.yml")
    parser.add_argument("--model")
    parser.set_defaults(command=_triage)
    sub = parser.add_subparsers(dest="triage_command", metavar="<action>")

    sample = sub.add_parser("sample", help="Write a CSV of reports for hand labelling")
    sample.add_argument("-n", type=int, default=100)
    sample.add_argument("--seed", type=int, default=0)
    sample.add_argument("-o", "--output", type=Path, default=Path("triage-sample.csv"))
    sample.set_defaults(command=_sample)

    check = sub.add_parser(
        "eval", help="Precision/recall of the decisions against a labelled CSV"
    )
    check.add_argument("labels", type=Path)
    check.set_defaults(command=_eval)

    cost = sub.add_parser("cost", help="LLM calls and tokens logged so far")
    cost.set_defaults(command=_cost)


def _triage(args):
    with connect(args.database_url) as conn:
        version = args.attack_version or latest_attack_version(conn)
        if not version:
            raise RuntimeError(
                "no ATT&CK version in the database; run `afp attack sync` first"
            )
        index = attack.load_index(conn, version)
        if args.dry_run:
            plan = run.plan(conn, index, limit=args.limit, retriage=args.retriage)
            print(
                f"triage dry run: {plan['reports']} reports, "
                f"{plan['rejected_by_heuristics']} rejected by heuristics, "
                f"{plan['llm_calls']} LLM calls, about {plan['prompt_chars'] // 4} input tokens "
                f"(chars/4), {plan['unreadable']} unreadable. No model was called."
            )
            return 0
        try:
            client = (
                None
                if args.heuristics_only
                else llm.from_config(args.provider, args.model)
            )
        except llm.LlmUnavailable as e:
            raise RuntimeError(f"{e} (or pass --heuristics-only)") from None
        counts = run.triage_reports(
            conn, index, client, limit=args.limit, retriage=args.retriage
        )
    print(
        "triage: "
        + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing to do")
    )


def _sample(args):
    with connect(args.database_url) as conn:
        rows = evaluate.sample(conn, args.n, args.seed)
    evaluate.write_sample(rows, args.output)
    print(
        f"wrote {len(rows)} reports to {args.output}; fill the label column with yes/no"
    )


def _eval(args):
    with connect(args.database_url) as conn:
        result = evaluate.evaluate(conn, evaluate.read_labels(args.labels))
    print(json.dumps(result, indent=2))
    return 0 if result["passes"] else 2


def _cost(args):
    with connect(args.database_url) as conn:
        rows = llm.cost_summary(conn)
    for r in rows:
        print(
            f"{r['purpose']:<8} {r['provider']}/{r['model']}: {r['calls']} calls "
            f"({r['failed']} failed), {r['input_tokens']} in / {r['output_tokens']} out tokens"
        )
    if not rows:
        print("no LLM calls logged")
