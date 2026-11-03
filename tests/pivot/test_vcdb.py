import csv
import json
from pathlib import Path

import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.ingest import vcdb

MAPPED = {
    "action.hacking.variety.Brute force",
    "action.malware.variety.Ransomware",
    "action.social.vector.Email",
    "attribute.integrity.variety.Software installation",
}


def doc(
    i,
    chain=None,
    hacking=("Brute force",),
    malware=("Ransomware",),
    version="1.4.0",
    notes="",
    year=2020,
):
    action = {}
    if hacking:
        action["hacking"] = {
            "variety": list(hacking),
            "vector": ["Web application"],
            "notes": "free text",
        }
    if malware:
        action["malware"] = {"variety": list(malware)}
    return {
        "incident_id": i,
        "schema_version": version,
        "action": action,
        "attribute": {"integrity": {"variety": ["Software installation"]}},
        "actor": {"external": {"variety": ["Unknown"]}},
        "victim": {"industry": "52", "employee_count": "101 to 1000"},
        "timeline": {"incident": {"year": year}},
        "plus": {"event_chain": chain or [], "analyst_notes": notes},
    }


STEPS = lambda *cats: [{"action": c, "actor": "ext"} for c in cats]  # noqa: E731


def test_veris_paths_skip_free_text():
    paths = vcdb.veris_paths(doc("a"))
    assert "action.hacking.variety.Brute force" in paths
    assert "attribute.integrity.variety.Software installation" in paths
    assert not any("free text" in p for p in paths)


def test_record_row_sequence_needs_two_steps():
    assert not vcdb.record_row(doc("a", STEPS("hak")))["has_sequence"]
    row = vcdb.record_row(doc("b", STEPS("hak", "mal")))
    assert (
        row["has_sequence"]
        and row["year"] == 2020
        and row["actor_types"] == ["external"]
    )
    assert row["victim_size"] == "101 to 1000"


def test_stats():
    docs = [
        doc("a", STEPS("hak", "mal")),  # sequence, both categories mapped
        doc(
            "b", STEPS("hak", "soc")
        ),  # sequence, no social path in record -> not fully mappable
        doc("c", STEPS("mal")),  # chain of one: no transition
        doc(
            "d",
            hacking=(),
            malware=("Unknown",),
            version="1.3.7",
            notes="Encoded by AI - skill",
        ),
        doc("a"),  # duplicate id
    ]
    s = vcdb.compute_stats(docs, MAPPED)
    assert (
        s["records"],
        s["distinct_incident_ids"],
        s["duplicate_incident_id_files"],
    ) == (5, 4, 1)
    assert s["veris_versions"] == {"1.4.0": 4, "1.3.7": 1}
    assert (s["with_event_chain"], s["with_sequence"]) == (3, 2)
    assert s["chain_length_histogram"] == {1: 1, 2: 2}
    assert s["sequence_fully_mappable"] == 1
    assert s["ai_encoded"] == 1 and s["sequence_ai_encoded"] == 0
    assert s["top_category_pairs"] == {"hacking>malware": 1, "hacking>social": 1}
    assert (
        s["records_with_any_mapped_path_pct"] == 100.0
    )  # attribute path is mapped in every record


def _mapping_repo(tmp_path):
    base = tmp_path / "mappings" / "veris-1.3.7" / "input"
    (base / "enterprise" / "csv").mkdir(parents=True)
    (base / "config.json").write_text(
        json.dumps(
            {
                "veris_version": "1.3.7",
                "mappings_version": "2.0",
                "attack_version": "12.1",
            }
        )
    )
    with (base / "enterprise" / "csv" / "veris1_3_7-mappings-enterprise.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as f:
        w = csv.writer(f)
        w.writerow(
            ["DATE DELIVERED", "VERIS PATH", "RELATIONSHIP TYPE", "TECHNIQUE ID"]
        )
        w.writerow(
            ["23/04/03", "action.hacking.variety.Brute force", "related-to", "T1110"]
        )
        w.writerow(
            [
                "23/04/03",
                "action.hacking.variety.Brute force",
                "related-to",
                "T1110.001",
            ]
        )
        w.writerow(
            ["23/04/03", "action.hacking.variety.Brute force", "related-to", "T1110"]
        )  # duplicate row
    return tmp_path


def test_read_mapping(tmp_path):
    label, rows = vcdb.read_mapping(_mapping_repo(tmp_path))
    assert label == "veris-1.3.7/mappings-2.0/attack-12.1"
    assert rows == [
        ("action.hacking.variety.Brute force", "T1110", "related-to"),
        ("action.hacking.variety.Brute force", "T1110.001", "related-to"),
    ]
    with pytest.raises(RuntimeError, match="no VERIS 1.4.0"):
        vcdb.read_mapping(tmp_path, "1.4.0")


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        yield conn


@pytest.mark.pivot_db
def test_load_is_idempotent_and_replaces_the_mapping_version(db, tmp_path):
    label, rows = vcdb.read_mapping(_mapping_repo(tmp_path))
    # the third file reuses incident_id "a" for a different record: both are keyed id~stem
    docs = [
        {**doc("a", STEPS("hak", "mal")), "_stem": "a"},
        {**doc("b"), "_stem": "b"},
        {**doc("a", STEPS("hak", "mal", "mal")), "_stem": "c"},
    ]
    dups = vcdb.duplicate_ids(docs)
    assert dups == {"a"}
    assert vcdb.load(db, docs, label, rows, dups) == {
        "veris_incidents": 3,
        "mapping_rows": 2,
    }
    vcdb.load(
        db, docs[1:], label, rows[:1], dups
    )  # re-run: smaller mapping, record "a~a" gone
    count = lambda t: db.execute(f"SELECT count(*) AS n FROM pivot.{t}").fetchone()[
        "n"
    ]  # noqa: E731
    assert (count("veris_incident"), count("veris_attack_map")) == (2, 1)
    row = db.execute(
        "SELECT has_sequence, jsonb_array_length(raw->'plus'->'event_chain') AS steps, "
        "raw ? '_stem' AS leaked FROM pivot.veris_incident WHERE id = 'a~c'"
    ).fetchone()
    assert row == {"has_sequence": True, "steps": 3, "leaked": False}
    names = {r["name"] for r in db.execute("SELECT name FROM pivot.source")}
    assert {"VERIS Community Database", "CTID VERIS-ATT&CK mapping"} <= names


@pytest.mark.pivot_db
def test_cli_vcdb_sync(db, scratch_db_url, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    vdir = tmp_path / "vcdb" / "data" / "json" / "validated"
    vdir.mkdir(parents=True)
    (vdir / "a.json").write_text(json.dumps(doc("a", STEPS("hak", "mal"))))
    argv = [
        "--database-url",
        scratch_db_url,
        "vcdb",
        "sync",
        "--repo-dir",
        str(tmp_path / "vcdb"),
        "--mapping-dir",
        str(_mapping_repo(tmp_path / "map")),
    ]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "VCDB: 1 incidents" in out and "with_sequence: 1" in out
    assert (
        json.loads((tmp_path / "data" / "pivot" / "vcdb-report.json").read_text())[
            "records"
        ]
        == 1
    )
