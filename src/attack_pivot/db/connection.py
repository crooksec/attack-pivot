"""Connections to the pivot PostgreSQL + Apache AGE database."""

import os

import psycopg
from psycopg.rows import dict_row

AGE_SESSION_SQL = """LOAD 'age'; SET search_path = ag_catalog, "$user", public;"""


def database_url(url=None):
    """Return the pivot database URL, from the argument or ``PIVOT_DATABASE_URL``."""
    url = url or os.environ.get("PIVOT_DATABASE_URL")
    if not url:
        raise RuntimeError("PIVOT_DATABASE_URL is not set")
    return url


def _configure_age(conn):
    """Connection hook: every AGE session must LOAD 'age' and set search_path."""
    conn.execute(AGE_SESSION_SQL)
    conn.commit()


def connect(url=None, autocommit=False):
    """
    Open a psycopg connection with AGE loaded and rows returned as dicts.

    :param str url: Overrides ``PIVOT_DATABASE_URL``.
    :param bool autocommit:
    :rtype: psycopg.Connection
    """
    conn = psycopg.connect(database_url(url), row_factory=dict_row)
    try:
        _configure_age(conn)
        conn.autocommit = autocommit
    except Exception:
        conn.close()
        raise
    return conn
