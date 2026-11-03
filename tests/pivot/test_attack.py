import json
from pathlib import Path

import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.normalize import attack

FIXTURE = Path(__file__).parent / "fixtures" / "attack_mini.json"


@pytest.fixture
def data():
    return attack.parse_bundle(json.loads(FIXTURE.read_text()), "20.0")


def test_parse_tactics_ordered_by_matrix(data):
    assert [(t["attack_id"], t["ord"]) for t in data.tactics] == [
        ("TA0001", 1),
        ("TA0002", 2),
    ]
    assert data.released == "2026-10-13"


def test_parse_techniques(data):
    by_id = {t["attack_id"]: t for t in data.techniques}
    assert by_id["T1059.001"]["parent_id"] == "T1059"
    assert by_id["T1059"]["parent_id"] is None
    assert by_id["T1059.001"]["tactic_ids"] == ["TA0002"]
    assert by_id["T1086"]["revoked"] and not by_id["T1086"]["deprecated"]
    assert by_id["T1099"]["deprecated"]


def test_parse_groups_skip_revoked_and_include_name_alias(data):
    assert [g["attack_group_id"] for g in data.groups] == ["G0016"]
    assert data.groups[0]["aliases"] == ["APT29", "Cozy Bear", "The Dukes"]


def test_revoked_chain_normalizes_to_current_id(data):
    index = attack.TechniqueIndex(
        {
            t["attack_id"]
            for t in data.techniques
            if not t["revoked"] and not t["deprecated"]
        },
        {r["from_id"]: r["to_id"] for r in data.replacements},
    )
    assert attack.normalize_technique("T1000", index) == (
        "T1059.001",
        ["T1000", "T1086", "T1059.001"],
    )
    assert attack.normalize_technique("T1086", index)[0] == "T1059.001"
    assert attack.normalize_technique("T1566", index) == ("T1566", ["T1566"])


def test_unmappable_ids_return_none(data):
    index = attack.TechniqueIndex(
        {
            t["attack_id"]
            for t in data.techniques
            if not t["revoked"] and not t["deprecated"]
        },
        {r["from_id"]: r["to_id"] for r in data.replacements},
    )
    assert (
        attack.normalize_technique("T1099", index)[0] is None
    )  # deprecated, no replacement
    assert attack.normalize_technique("T1064", index)[0] is None  # replacement cycle
    assert attack.normalize_technique("T9999", index)[0] is None  # unknown


def test_fetch_uses_cache(tmp_path):
    (tmp_path / "enterprise-attack-20.0.json").write_text(FIXTURE.read_text())
    assert attack.fetch_bundle("20.0", tmp_path)["type"] == "bundle"


@pytest.mark.pivot_db
def test_sync_loads_database_and_is_idempotent(scratch_db_url, data):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        first = attack.load(conn, data)
        attack.load(conn, data)
        assert first == {"tactics": 2, "techniques": 8, "replacements": 4, "groups": 1}
        count = lambda t: conn.execute(
            f"SELECT count(*) AS n FROM pivot.{t}"
        ).fetchone()["n"]
        assert (
            count("technique"),
            count("technique_replacement"),
            count("actor_alias"),
        ) == (8, 4, 3)
        index = attack.load_index(conn, "20.0")
        assert attack.normalize_technique("T1000", index)[0] == "T1059.001"


@pytest.mark.pivot_db
def test_cli_attack_sync(scratch_db_url, tmp_path, monkeypatch, capsys):
    (tmp_path / "pivot" / "attack").mkdir(parents=True)
    (tmp_path / "pivot" / "attack" / "enterprise-attack-20.0.json").write_text(
        FIXTURE.read_text()
    )
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    main(["--database-url", scratch_db_url, "db", "init"])
    assert (
        main(["--database-url", scratch_db_url, "attack", "sync", "--version", "20.0"])
        == 0
    )
    assert "ATT&CK 20.0: 2 tactics, 8 techniques" in capsys.readouterr().out
