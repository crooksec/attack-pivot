import re
from pathlib import Path

import psycopg
import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations

SPEC_TABLES = {
    "source", "report", "incident", "report_incident", "flow", "action_obs", "transition_obs",
    "actor", "actor_alias", "flow_actor", "flow_context", "attack_version", "technique",
    "technique_replacement", "tactic", "model_run", "transition_estimate", "analytic",
    "analytic_technique", "veris_incident", "veris_attack_map", "coverage_layer", "coverage_item",
}  # fmt: skip

pytestmark = pytest.mark.pivot_db


def _tables(conn):
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'pivot'"
    )
    return {r["table_name"] for r in rows}


def test_init_creates_spec_schema_and_graph(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.init(conn)
        applied = migrations.migrate(conn)
        assert applied == [
            "0001_init",
            "0002_estimate_precision",
            "0003_source_review",
        ]
        assert SPEC_TABLES <= _tables(conn)
        graphs = [
            r["name"] for r in conn.execute("SELECT name FROM ag_catalog.ag_graph")
        ]
        assert graphs == ["pivot_graph"]


def test_migrate_is_idempotent(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        before = _tables(conn)
        assert migrations.migrate(conn) == []
        migrations.init(conn)
        assert _tables(conn) == before
        assert (
            conn.execute("SELECT count(*) AS n FROM pivot.schema_migration").fetchone()[
                "n"
            ]
            == 3
        )


def test_cli_db_init_twice(scratch_db_url, capsys):
    assert main(["--database-url", scratch_db_url, "db", "init"]) == 0
    assert "0001_init" in capsys.readouterr().out
    assert main(["--database-url", scratch_db_url, "db", "init"]) == 0
    assert "up to date" in capsys.readouterr().out


def test_changed_applied_migration_is_rejected(scratch_db_url, tmp_path):
    (tmp_path / "0001_a.sql").write_text("CREATE TABLE pivot.t1 (id int);")
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn, tmp_path)
        (tmp_path / "0001_a.sql").write_text("CREATE TABLE pivot.t1 (id bigint);")
        with pytest.raises(RuntimeError, match="changed after it was applied"):
            migrations.migrate(conn, tmp_path)


def test_constraints(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        flow = conn.execute(
            "INSERT INTO pivot.flow (origin) VALUES ('manual') RETURNING id"
        ).fetchone()["id"]
        a = [
            conn.execute(
                "INSERT INTO pivot.action_obs (flow_id, node_ref) VALUES (%s, %s) RETURNING id",
                (flow, ref),
            ).fetchone()["id"]
            for ref in ("a", "b")
        ]
        insert = (
            "INSERT INTO pivot.transition_obs (flow_id, src_action, dst_action, order_basis, "
            "evidence_quote) VALUES (%s, %s, %s, %s, %s)"
        )
        conn.execute(insert, (flow, a[0], a[1], "explicit", "x" * 200))
        for basis, quote in (("bogus", None), ("explicit", "x" * 201)):
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(insert, (flow, a[0], a[1], basis, quote))
            conn.rollback()
            conn.execute('SET search_path = ag_catalog, "$user", public')


def test_one_active_model_run(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        conn.execute("INSERT INTO pivot.model_run (is_active) VALUES (true)")
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute("INSERT INTO pivot.model_run (is_active) VALUES (true)")


def test_no_code_drops_the_graph():
    """Defence in depth: the graph has its own schema now, but nothing should drop it anyway."""
    root = Path(__file__).resolve().parents[2]
    for path in [
        *(root / "src" / "attack_pivot").rglob("*.py"),
        *(root / "migrations").rglob("*.sql"),
    ]:
        code = "\n".join(
            l
            for l in path.read_text().splitlines()
            if not l.lstrip().startswith(("--", "#"))
        )
        assert not re.search(r"drop_graph", code, re.I), path
