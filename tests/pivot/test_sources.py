from pathlib import Path

import pytest

from attack_pivot.cli import main
from attack_pivot.collect import registry
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations

SEED = Path(__file__).resolve().parents[2] / "docs" / "pivot" / "sources.seed.yaml"


def write(tmp_path, text):
    path = tmp_path / "seed.yaml"
    path.write_text(text)
    return path


def test_read_real_seed():
    rows = registry.read_seed(SEED)
    by_name = {r["name"]: r for r in rows}
    assert len(rows) == len(by_name) > 40
    enabled = {r["name"] for r in rows if r["enabled"]}
    assert enabled == {
        "MITRE CAR",
        "VERIS Community Database",
        "CTID VERIS-ATT&CK mapping",
        "Attack Flow upstream corpus",
    }
    # defaults applied: disabled, clear, 5 s rate limit
    dfir = by_name["The DFIR Report"]
    assert not dfir["enabled"] and dfir["default_tlp"] == "clear"
    assert dfir["collector_config"]["rate_limit_seconds"] == 5
    assert by_name["Health-ISAC"]["default_tlp"] == "amber"
    assert by_name["Health-ISAC"]["collector"] == "manual"


@pytest.mark.parametrize(
    "line, message",
    [
        ("source_class: bogus, collector: rss", "source_class 'bogus'"),
        ("source_class: vendor, collector: scrape", "collector 'scrape'"),
        (
            "source_class: vendor, collector: rss, default_tlp: white",
            "default_tlp 'white'",
        ),
        ("source_class: vendor, collector: rss, reliability: Z", "reliability 'Z'"),
    ],
)
def test_read_seed_validates(tmp_path, line, message):
    path = write(
        tmp_path,
        f"defaults: {{default_tlp: clear}}\nsources:\n  - {{name: X, {line}}}\n",
    )
    with pytest.raises(RuntimeError, match=message):
        registry.read_seed(path)


def test_read_seed_rejects_duplicates(tmp_path):
    entry = "{name: X, source_class: vendor, collector: rss, default_tlp: clear}"
    with pytest.raises(RuntimeError, match="duplicate"):
        registry.read_seed(write(tmp_path, f"sources:\n  - {entry}\n  - {entry}\n"))


def test_unreviewed_licence():
    assert registry.unreviewed_licence(None)
    assert registry.unreviewed_licence("verify (repo licence file)")
    assert registry.unreviewed_licence("Apache-2.0 (verify)")
    assert not registry.unreviewed_licence("Apache-2.0")


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        yield conn


@pytest.mark.pivot_db
def test_load_is_idempotent_and_keeps_db_owned_state(db):
    rows = registry.read_seed(SEED)
    first = registry.load(db, rows)
    assert first == {"inserted": len(rows), "updated": 0, "not_in_seed": []}
    car = db.execute(
        "SELECT enabled, reviewed_by FROM pivot.source WHERE name = 'MITRE CAR'"
    ).fetchone()
    assert car == {"enabled": True, "reviewed_by": "seed"}

    # a reviewer enables one source and disables a seed-enabled one; reloading keeps both
    registry.enable(db, "CISA Cybersecurity Advisories", "pcrook")
    registry.disable(db, "MITRE CAR")
    again = registry.load(db, rows)
    assert again["inserted"] == 0 and again["updated"] == len(rows)
    state = {
        r["name"]: r["enabled"]
        for r in db.execute("SELECT name, enabled FROM pivot.source")
    }
    assert state["CISA Cybersecurity Advisories"] and not state["MITRE CAR"]


@pytest.mark.pivot_db
def test_enable_fails_closed_without_a_verified_licence(db):
    registry.load(db, registry.read_seed(SEED))
    with pytest.raises(RuntimeError, match="verified licence"):
        registry.enable(db, "Red Canary Blog", "pcrook")  # licence is NULL
    with pytest.raises(RuntimeError, match="verified licence"):
        registry.enable(db, "ORKL", "pcrook")
    with pytest.raises(RuntimeError, match="--reviewed-by"):
        registry.enable(db, "Red Canary Blog", "", licence="CC BY 4.0")
    registry.enable(db, "Red Canary Blog", "pcrook", licence="CC BY 4.0")
    row = db.execute(
        "SELECT enabled, licence, reviewed_by FROM pivot.source WHERE name = 'Red Canary Blog'"
    ).fetchone()
    assert row == {"enabled": True, "licence": "CC BY 4.0", "reviewed_by": "pcrook"}
    with pytest.raises(RuntimeError, match="no source named"):
        registry.enable(db, "Nope", "pcrook", licence="MIT")


@pytest.mark.pivot_db
def test_load_reports_sources_outside_the_seed(db):
    db.execute(
        "INSERT INTO pivot.source (name, source_class) VALUES ('Manual import', 'other')"
    )
    db.commit()
    assert registry.load(db, registry.read_seed(SEED))["not_in_seed"] == [
        "Manual import"
    ]


@pytest.mark.pivot_db
def test_cli_sources(scratch_db_url, capsys):
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    assert main([*url, "sources", "load", str(SEED)]) == 0
    assert "inserted" in capsys.readouterr().out
    assert main([*url, "sources", "list", "--enabled"]) == 0
    assert "4 sources, 4 enabled" in capsys.readouterr().out
    assert main([*url, "sources", "enable", "ORKL", "--reviewed-by", "x"]) == 1
