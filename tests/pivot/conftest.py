import os

import pytest

# The pivot dependency group is optional: without it (e.g. `poetry install --with api` only) the
# pivot tests are skipped at collection instead of failing the upstream suite.
try:
    import psycopg  # noqa: F401
    import scipy  # noqa: F401
except ImportError:
    collect_ignore_glob = ["test_*.py"]


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "pivot_db: needs a running pivot-db (PIVOT_DATABASE_URL)"
    )


@pytest.fixture
def pivot_url():
    url = os.environ.get("PIVOT_DATABASE_URL")
    if not url:
        pytest.skip("PIVOT_DATABASE_URL not set")
    return url


@pytest.fixture
def scratch_db_url(pivot_url):
    """A throwaway database on the pivot server, dropped after the test."""
    import uuid

    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    name = f"pivot_test_{uuid.uuid4().hex[:10]}"
    admin = psycopg.connect(
        make_conninfo(pivot_url, dbname="postgres"), autocommit=True
    )
    admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield make_conninfo(
            pivot_url, **{**conninfo_to_dict(pivot_url), "dbname": name}
        )
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()


@pytest.fixture
def corpus_db(scratch_db_url):
    """A scratch database with the 41-flow seed corpus ingested against a fake ATT&CK 'test'."""
    import re
    from pathlib import Path

    from attack_pivot.db import connect, migrate
    from attack_pivot.ingest import load
    from attack_pivot.ingest.afb import parse_afb_file

    corpus = sorted((Path(__file__).resolve().parents[2] / "corpus").glob("*.afb"))
    ids = {
        a.technique_id
        for p in corpus
        for a in parse_afb_file(p).actions
        if a.technique_id and re.fullmatch(r"T\d{4}(\.\d{3})?", a.technique_id)
    }
    with connect(scratch_db_url) as conn:
        migrate.migrate(conn)
        conn.execute(
            "INSERT INTO pivot.attack_version (version, released) VALUES ('test', '2026-10-13')"
        )
        for n, tactic in enumerate(("TA0001", "TA0002", "TA0003"), start=1):
            conn.execute(
                "INSERT INTO pivot.tactic (attack_id, version, name, ord) VALUES (%s, 'test', %s, %s)",
                (tactic, tactic, n),
            )
        for k, tid in enumerate(sorted(ids)):
            tactics = (
                ["TA0001", "TA0002"]
                if k % 5 == 0
                else [("TA0001", "TA0002", "TA0003")[k % 3]]
            )
            conn.execute(
                "INSERT INTO pivot.technique (attack_id, version, name, parent_id, tactic_ids) "
                "VALUES (%s, 'test', %s, %s, %s)",
                (tid, tid, tid.split(".")[0] if "." in tid else None, tactics),
            )
        conn.commit()
        # a parent technique must exist for every sub-technique
        for tid in sorted(ids):
            if "." in tid:
                conn.execute(
                    "INSERT INTO pivot.technique (attack_id, version, name, tactic_ids) VALUES (%s, 'test', %s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (tid.split(".")[0], tid.split(".")[0], ["TA0001"]),
                )
        conn.commit()
        load.ingest_paths(conn, corpus, version="test")
        yield conn
