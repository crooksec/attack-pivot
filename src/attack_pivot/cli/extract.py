"""``afp extract``."""

from attack_pivot.db import connect
from attack_pivot.extract import api, run
from attack_pivot.ingest.load import latest_attack_version


def register(subparsers):
    parser = subparsers.add_parser(
        "extract",
        help="Extract candidate reports through the API job pipeline and ingest the flows",
    )
    parser.add_argument("--limit", type=int, help="Extract at most N reports")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--provider", help="Provider id configured in the API")
    parser.add_argument("--model")
    parser.add_argument(
        "--api-url",
        help="API base URL (default: ATTACK_FLOW_API_URL or http://localhost:8000/api/v1)",
    )
    parser.add_argument(
        "--attack-version", help="ATT&CK version to normalize to (default: latest)"
    )
    parser.add_argument(
        "--timeout", type=float, default=900.0, help="Seconds to wait for one job"
    )
    parser.set_defaults(command=_extract)


def _extract(args):
    with connect(args.database_url) as conn:
        version = args.attack_version or latest_attack_version(conn)
        if not version:
            raise RuntimeError(
                "no ATT&CK version in the database; run `afp attack sync` first"
            )
        todo = len(run.pending(conn, args.limit))
        if not todo:
            print("no candidate reports; run `afp triage` first")
            return 0
        with api.ApiClient(args.api_url) as client:
            counts = run.extract_reports(
                conn,
                client,
                version,
                args.limit,
                args.concurrency,
                args.provider,
                args.model,
                args.timeout,
            )
    print("extract: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
