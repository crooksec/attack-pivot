"""``afp ingest`` command."""

from pathlib import Path

from attack_pivot.db import connect
from attack_pivot.ingest import load


def register(subparsers):
    parser = subparsers.add_parser(
        "ingest", help="Ingest .afb (upstream corpus) and STIX .json flows"
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Flow files")
    parser.add_argument(
        "--attack-version", help="ATT&CK version (default: latest synced)"
    )
    parser.add_argument(
        "--tlp",
        choices=["clear", "green", "amber", "amber+strict", "red"],
        help="TLP for STIX imports (default: amber, fail closed)",
    )
    parser.set_defaults(command=_ingest)


def _ingest(args):
    with connect(args.database_url) as conn:
        ingested, skipped, counts = load.ingest_paths(
            conn, args.paths, version=args.attack_version, tlp=args.tlp
        )
    print(
        f"ingested {len(ingested)} flows, skipped {len(skipped)} already present; "
        + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    )
