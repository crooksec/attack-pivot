"""Idempotent SQL migrations for the pivot database."""

import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

GRAPH_NAME = "pivot_graph"

EXTENSION_SQL = "CREATE EXTENSION IF NOT EXISTS age;"

# AGE keeps the graph's tables in a Postgres schema named after the graph (``pivot_graph``), so
# the relational ``pivot`` schema is not shared with it and dropping the graph cannot drop data.
LEDGER_SQL = """
CREATE SCHEMA IF NOT EXISTS pivot;
CREATE TABLE IF NOT EXISTS pivot.schema_migration (
    version text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
"""

CREATE_GRAPH_SQL = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = '{GRAPH_NAME}') THEN
        PERFORM ag_catalog.create_graph('{GRAPH_NAME}');
    END IF;
END
$$;
"""


def migrations_dir():
    """
    Directory holding numbered ``*.sql`` migrations: ``PIVOT_MIGRATIONS_DIR`` or the repo's
    ``migrations/pivot``.

    :rtype: Path
    """
    override = os.environ.get("PIVOT_MIGRATIONS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "migrations" / "pivot"


def init(conn):
    """Create the AGE extension, the ``pivot`` graph and schema, and the migration ledger."""
    conn.execute(EXTENSION_SQL)
    conn.execute(CREATE_GRAPH_SQL)
    conn.execute(LEDGER_SQL)
    conn.commit()


def migrate(conn, directory=None):
    """
    Apply pending numbered migrations, each in its own transaction.

    :param psycopg.Connection conn:
    :param Path directory: Defaults to :func:`migrations_dir`.
    :return: Versions applied by this call.
    :rtype: list[str]
    """
    init(conn)
    directory = Path(directory) if directory else migrations_dir()
    files = sorted(p for p in directory.glob("[0-9]*.sql"))
    applied = {
        row["version"]: row["checksum"]
        for row in conn.execute("SELECT version, checksum FROM pivot.schema_migration")
    }
    done = []
    for path in files:
        version = path.stem
        sql = path.read_text()
        checksum = hashlib.sha256(sql.encode()).hexdigest()
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError(f"migration {version} changed after it was applied")
            continue
        logger.info("applying %s", version)
        try:
            conn.execute(sql)
            conn.execute(
                "INSERT INTO pivot.schema_migration (version, checksum) VALUES (%s, %s)",
                (version, checksum),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        done.append(version)
    return done
