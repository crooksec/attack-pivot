"""``afp car`` commands."""

import json
import os
from pathlib import Path

from attack_pivot.db import connect
from attack_pivot.ingest import car
from attack_pivot.ingest.load import latest_attack_version


def register(subparsers):
    parser = subparsers.add_parser("car", help="MITRE CAR detection analytics")
    sub = parser.add_subparsers(dest="car_command", required=True, metavar="<action>")
    sync = sub.add_parser(
        "sync", help="Clone/pull CAR, load analytics, build the CAR baseline layer"
    )
    sync.add_argument(
        "--repo-dir", type=Path, help="Use this checkout instead of cloning/pulling"
    )
    sync.add_argument(
        "--attack-version", help="ATT&CK version for the layer (default: latest synced)"
    )
    sync.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Layer file (default: DATA_DIR/pivot/layers/car-baseline.json)",
    )
    sync.set_defaults(command=_sync)


def _sync(args):
    directory = args.repo_dir or car.update_repo()
    parsed = car.read_analytics(directory)
    with connect(args.database_url) as conn:
        counts = car.load(conn, parsed)
        version = args.attack_version or latest_attack_version(conn) or "20.0"
        layer = car.baseline_layer(conn, version)
        car.store_baseline(conn, layer, version)
    out = (
        args.output
        or Path(os.environ.get("DATA_DIR", "data"))
        / "pivot"
        / "layers"
        / "car-baseline.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(layer, indent=2))
    print(
        f"CAR: {counts['analytics']} analytics, {counts['technique_links']} technique links; "
        f"baseline layer: {len(layer['techniques'])} techniques -> {out}"
    )
