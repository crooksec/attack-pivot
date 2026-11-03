"""``afp vcdb`` commands."""

import json
import os
from pathlib import Path

from attack_pivot.db import connect
from attack_pivot.ingest import vcdb


def register(subparsers):
    parser = subparsers.add_parser(
        "vcdb", help="VERIS Community Database and ATT&CK mapping"
    )
    sub = parser.add_subparsers(dest="vcdb_command", required=True, metavar="<action>")
    sync = sub.add_parser(
        "sync", help="Clone/pull VCDB and the mapping, load both, print the report"
    )
    sync.add_argument(
        "--map-version",
        default=vcdb.DEFAULT_MAP_VERSION,
        help="VERIS version of the mapping",
    )
    sync.add_argument(
        "--repo-dir", type=Path, help="VCDB checkout (default: clone/pull)"
    )
    sync.add_argument(
        "--mapping-dir",
        type=Path,
        help="attack_to_veris checkout (default: clone/pull)",
    )
    sync.set_defaults(command=_sync)


def _sync(args):
    if args.repo_dir and args.mapping_dir:
        vcdb_dir, mapping_dir = args.repo_dir, args.mapping_dir
    else:
        vcdb_dir, mapping_dir = vcdb.update_repos(args.repo_dir, args.mapping_dir)
    label, rows = vcdb.read_mapping(mapping_dir, args.map_version)
    mapped_paths = {path for path, _, _ in rows}
    stats = vcdb.compute_stats(vcdb.read_records(vcdb_dir), mapped_paths)
    with connect(args.database_url) as conn:
        counts = vcdb.load(
            conn,
            vcdb.read_records(vcdb_dir),
            label,
            rows,
            vcdb.duplicate_ids(vcdb.read_records(vcdb_dir)),
        )
    out = Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "vcdb-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"mapping": label, **stats}, indent=2))
    print(
        f"VCDB: {counts['veris_incidents']} incidents; mapping {label}: {counts['mapping_rows']} rows"
    )
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"report -> {out}")
