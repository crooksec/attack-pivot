import json
from pathlib import Path

import pytest
import yaml

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.ingest import car
from attack_pivot.normalize import attack

MINI = json.loads((Path(__file__).parent / "fixtures" / "attack_mini.json").read_text())
REAL_REPO = Path(__file__).resolve().parents[2] / "data" / "pivot" / "repos" / "car"

A1 = {
    "id": "CAR-2020-09-001",
    "title": "PowerShell",
    "information_domain": "Host",
    "platforms": ["Windows"],
    "data_model_references": ["process/create/command_line"],
    "coverage": [
        {
            "technique": "T1059",
            "tactics": ["TA0002"],
            "subtechniques": ["T1059.001"],
            "coverage": "Moderate",
        },
        {"technique": "T1566", "tactics": ["TA0001", "TA0002"], "coverage": "Low"},
    ],
}
A2 = {  # a legacy ID that v20 revoked: T1086 -> T1059.001; same pair listed twice, High wins
    "id": "CAR-2013-01-002",
    "title": "Old",
    "coverage": [
        {"technique": "T1086", "tactics": ["TA0002"], "coverage": "Low"},
        {
            "technique": "T1059",
            "subtechniques": ["T1059.001"],
            "tactics": ["TA0002"],
            "coverage": "High",
        },
    ],
}
A3 = {"id": "CAR-2015-07-001", "title": "No coverage", "information_domain": "Host"}


def _repo(tmp_path, *docs):
    (tmp_path / "analytics").mkdir()
    for d in docs:
        (tmp_path / "analytics" / f"{d['id']}.yaml").write_text(yaml.safe_dump(d))
    return tmp_path


def test_parse_analytic_counts_technique_and_subtechniques():
    analytic, links = car.parse_analytic(A1)
    assert analytic["url"] == "https://car.mitre.org/analytics/CAR-2020-09-001/"
    assert analytic["data_model_refs"] == ["process/create/command_line"]
    by_id = {l["technique_id"]: l for l in links}
    assert set(by_id) == {"T1059", "T1059.001", "T1566"}
    assert by_id["T1059.001"]["tactic_id"] == "TA0002"  # single tactic kept
    assert (
        by_id["T1566"]["tactic_id"] is None
    )  # two tactics: ambiguous, kept only in raw
    assert by_id["T1566"]["coverage"] == "Low"


def test_parse_analytic_without_coverage_and_duplicate_pairs():
    assert car.parse_analytic(A3)[1] == []
    links = {l["technique_id"]: l for l in car.parse_analytic(A2)[1]}
    assert links["T1059.001"]["coverage"] == "High"


def test_read_analytics_requires_files(tmp_path):
    with pytest.raises(RuntimeError, match="no analytics"):
        car.read_analytics(tmp_path)


@pytest.mark.skipif(not REAL_REPO.exists(), reason="CAR checkout not present")
def test_real_repo_analytic_count_matches_files():
    files = list((REAL_REPO / "analytics").glob("*.yaml"))
    parsed = car.read_analytics(REAL_REPO)
    assert len(parsed) == len(files) == len({a["id"] for a, _ in parsed})


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        attack.load(conn, attack.parse_bundle(MINI, "20.0"))
        yield conn


@pytest.mark.pivot_db
def test_load_is_idempotent_and_removes_stale(db, tmp_path):
    parsed = car.read_analytics(_repo(tmp_path, A1, A2, A3))
    first = car.load(db, parsed)
    assert first == {"analytics": 3, "technique_links": 6, "removed": 0}
    assert car.load(db, parsed)["removed"] == 0
    n = lambda t: db.execute(f"SELECT count(*) AS n FROM pivot.{t}").fetchone()[
        "n"
    ]  # noqa: E731
    assert (n("analytic"), n("analytic_technique")) == (3, 6)
    assert car.load(db, parsed[:2])["removed"] == 1
    assert n("analytic") == 2
    assert (
        db.execute(
            "SELECT count(*) AS n FROM pivot.source WHERE name = 'MITRE CAR'"
        ).fetchone()["n"]
        == 1
    )


@pytest.mark.pivot_db
def test_links_are_normalized_to_the_attack_version(db, tmp_path):
    car.load(db, car.read_analytics(_repo(tmp_path, A1, A2)))
    links, unmapped = car.normalized_links(db, "20.0")
    pairs = {(l["analytic_id"], l["technique_id"]): l for l in links}
    assert ("CAR-2013-01-002", "T1086") not in pairs
    assert (
        pairs[("CAR-2013-01-002", "T1059.001")]["coverage"] == "High"
    )  # merged with the T1086 link
    assert unmapped == []
    # stored rows still carry CAR's declared IDs
    assert (
        db.execute(
            "SELECT count(*) AS n FROM pivot.analytic_technique WHERE technique_id = 'T1086'"
        ).fetchone()["n"]
        == 1
    )


@pytest.mark.pivot_db
def test_baseline_layer_shape_and_store(db, tmp_path):
    car.load(db, car.read_analytics(_repo(tmp_path, A1, A2, A3)))
    layer = car.baseline_layer(db, "20.0")
    assert layer["versions"] == {"layer": "4.5", "attack": "20", "navigator": "5.1.0"}
    assert layer["domain"] == "enterprise-attack"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1059", "T1059.001", "T1566"}
    assert (
        by_id["T1059"]["showSubtechniques"]
        and "showSubtechniques" not in by_id["T1059.001"]
    )
    assert "CAR-2013-01-002: Old" in by_id["T1059.001"]["comment"]
    assert all(t["enabled"] and t["color"].startswith("#") for t in layer["techniques"])
    car.store_baseline(db, layer, "20.0")
    car.store_baseline(db, layer, "20.0")
    row = db.execute(
        "SELECT count(*) AS layers, (SELECT count(*) FROM pivot.coverage_item) AS items FROM pivot.coverage_layer"
    ).fetchone()
    assert row == {"layers": 1, "items": 3}


@pytest.mark.pivot_db
def test_cli_car_sync(db, scratch_db_url, tmp_path, capsys):
    repo = (
        _repo(tmp_path / "repo", A1, A2)
        if (tmp_path / "repo").mkdir() is None
        else None
    )
    out = tmp_path / "layer.json"
    argv = [
        "--database-url",
        scratch_db_url,
        "car",
        "sync",
        "--repo-dir",
        str(repo),
        "-o",
        str(out),
    ]
    assert main(argv) == 0
    assert "CAR: 2 analytics" in capsys.readouterr().out
    assert json.loads(out.read_text())["name"] == "CAR baseline"
