import re
import shutil
from pathlib import Path

import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.ingest import load
from attack_pivot.ingest.afb import parse_afb_file

ROOT = Path(__file__).resolve().parents[2]
CORPUS = sorted((ROOT / "corpus").glob("*.afb"))

pytestmark = pytest.mark.pivot_db


def _seed_attack(conn, version="test"):
    """A fake ATT&CK release that knows every Enterprise-style ID used by the corpus."""
    ids = {
        a.technique_id
        for p in CORPUS
        for a in parse_afb_file(p).actions
        if a.technique_id and re.fullmatch(r"T\d{4}(\.\d{3})?", a.technique_id)
    }
    conn.execute(
        "INSERT INTO pivot.attack_version (version, released) VALUES (%s, '2026-10-13')",
        (version,),
    )
    for tid in sorted(ids):
        conn.execute(
            "INSERT INTO pivot.technique (attack_id, version, name) VALUES (%s, %s, %s)",
            (tid, version, tid),
        )
    conn.commit()
    return ids


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        _seed_attack(conn)
        yield conn


def _count(conn, table):
    return conn.execute(f"SELECT count(*) AS n FROM pivot.{table}").fetchone()["n"]


def test_ingest_seed_corpus(db):
    ingested, skipped, counts = load.ingest_paths(db, CORPUS)
    assert (len(ingested), skipped) == (41, [])
    assert [
        _count(db, t) for t in ("flow", "incident", "report", "report_incident")
    ] == [41] * 4
    assert _count(db, "action_obs") == 952
    assert _count(db, "transition_obs") == 1070
    assert (
        counts["unmappable"] == 36
    )  # MITRE ATLAS IDs: every action of the two OpenClaw flows
    # one incident per flow
    assert (
        db.execute(
            "SELECT max(n) AS m FROM (SELECT count(*) n FROM pivot.flow GROUP BY incident_id) x"
        ).fetchone()["m"]
        == 1
    )
    flows = db.execute(
        "SELECT DISTINCT origin, review_status, tlp, attack_version FROM pivot.flow"
    ).fetchall()
    assert flows == [
        {
            "origin": "upstream_corpus",
            "review_status": "accepted",
            "tlp": "clear",
            "attack_version": "test",
        }
    ]


def test_original_ids_are_kept_and_unmappable_are_null(db):
    load.ingest_paths(db, [ROOT / "corpus" / "OpenClaw.afb"])
    row = db.execute(
        "SELECT technique_id, technique_id_original FROM pivot.action_obs "
        "WHERE technique_id_original LIKE 'AML.%' LIMIT 1"
    ).fetchone()
    assert row["technique_id"] is None and row["technique_id_original"].startswith(
        "AML."
    )


def test_previously_zero_edge_flows_have_labeled_transitions(db):
    load.ingest_paths(db, CORPUS)
    rows = db.execute(
        "SELECT f.name, count(*) FILTER (WHERE t.src_technique IS NOT NULL AND t.dst_technique IS NOT NULL) AS labeled "
        "FROM pivot.flow f JOIN pivot.transition_obs t ON t.flow_id = f.id "
        "WHERE f.name IN ('Turla - Carbon Emulation Plan', 'Turla - Snake Emulation Plan', 'Equifax Breach (with Mitigations/Detections)', "
        "'ToolShell Vulnerability in Sharepoint', 'OpenClaw Command & Control via Prompt Injection', 'Example Attack Tree') GROUP BY f.name"
    ).fetchall()
    labeled = {r["name"]: r["labeled"] for r in rows}
    # No Enterprise technique labels: an unlabeled attack tree and two ATLAS-only flows.
    assert labeled.pop("Example Attack Tree") == 0
    assert labeled.pop("OpenClaw Command & Control via Prompt Injection") == 0
    assert all(n > 0 for n in labeled.values()) and len(labeled) == 4


def test_attack_tree_is_unordered_everything_else_explicit(db):
    load.ingest_paths(db, CORPUS)
    rows = db.execute(
        "SELECT f.name, t.order_basis FROM pivot.transition_obs t JOIN pivot.flow f ON f.id = t.flow_id "
        "GROUP BY f.name, t.order_basis"
    ).fetchall()
    unordered = {r["name"] for r in rows if r["order_basis"] == "unordered"}
    assert unordered == {"Example Attack Tree"}
    assert {r["order_basis"] for r in rows} == {"explicit", "unordered"}


def test_reingest_is_idempotent(db):
    load.ingest_paths(db, CORPUS)
    ingested, skipped, _ = load.ingest_paths(db, CORPUS)
    assert (ingested, len(skipped)) == ([], 41)
    assert _count(db, "flow") == 41


def test_requires_synced_attack_version(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        with pytest.raises(RuntimeError, match="afp attack sync"):
            load.ingest_paths(conn, CORPUS[:1])


def test_actor_exact_alias_match_and_unmatched(db):
    actor = db.execute(
        "INSERT INTO pivot.actor (attack_group_id, name) VALUES ('G0050', 'APT32') RETURNING id"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO pivot.actor_alias (actor_id, alias) VALUES (%s, 'OceanLotus'), (%s, 'APT32')",
        (actor, actor),
    )
    db.commit()
    load.ingest_paths(db, [ROOT / "corpus" / "Cobalt Kitty Campaign.afb"])
    row = db.execute(
        "SELECT a.attack_group_id, fa.basis, fa.attribution_confidence FROM pivot.flow_actor fa "
        "JOIN pivot.actor a ON a.id = fa.actor_id"
    ).fetchone()
    assert row == {
        "attack_group_id": "G0050",
        "basis": "alias_exact",
        "attribution_confidence": 1.0,
    }


def test_stix_import_fails_closed_to_amber(db, tmp_path):
    shutil.copy(
        ROOT / "tests" / "fixtures" / "matrix-flow.json", tmp_path / "matrix-flow.json"
    )
    load.ingest_paths(db, [tmp_path / "matrix-flow.json"])
    row = db.execute(
        "SELECT origin, tlp, review_status, stix IS NOT NULL AS has_stix FROM pivot.flow"
    ).fetchone()
    assert row == {
        "origin": "stix_import",
        "tlp": "amber",
        "review_status": "unreviewed",
        "has_stix": True,
    }
    load.ingest_paths(db, [ROOT / "tests" / "fixtures" / "flow1.json"], tlp="clear")
    assert (
        db.execute("SELECT tlp FROM pivot.flow WHERE name = 'Test Flow 1'").fetchone()[
            "tlp"
        ]
        == "clear"
    )


def test_cli_ingest(scratch_db_url, capsys):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        _seed_attack(conn)
    argv = ["--database-url", scratch_db_url, "ingest", *map(str, CORPUS)]
    assert main(argv) == 0
    assert "ingested 41 flows, skipped 0" in capsys.readouterr().out
    assert main(argv) == 0
    assert "ingested 0 flows, skipped 41" in capsys.readouterr().out
