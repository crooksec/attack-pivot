"""Helpers for running openCypher against Apache AGE through psycopg."""

import json
import re

from attack_pivot.db.migrate import GRAPH_NAME

_TYPE_SUFFIX = re.compile(r"::(vertex|edge|path|numeric)\b")


def parse_agtype(text):
    """
    Parse an ``agtype`` value returned as text into Python data.

    Vertices and edges become dicts (``id``, ``label``, ``properties``, ...).

    :param str text:
    """
    if text is None:
        return None
    return json.loads(_TYPE_SUFFIX.sub("", text))


def cypher(conn, query, params=None, columns=("result",)):
    """
    Run one Cypher statement against the pivot graph.

    Parameters are passed as an agtype map and referenced as ``$name`` in the query. The
    connection must come from :func:`attack_pivot.db.connect` (AGE loaded, search_path set).

    :param psycopg.Connection conn:
    :param str query: openCypher text; must not contain ``$$``.
    :param dict params: JSON-serializable parameters.
    :param tuple columns: Names of the RETURN columns (all ``agtype``).
    :return: A list of dicts keyed by column, values parsed with :func:`parse_agtype`.
    :rtype: list[dict]
    """
    cols = ", ".join(f"{c} agtype" for c in columns)
    sql = f"SELECT * FROM cypher('{GRAPH_NAME}', $$ {query} $$, %s) AS ({cols})"
    cur = conn.execute(sql, (json.dumps(params or {}),))
    if cur.description is None:
        return []
    return [{k: parse_agtype(v) for k, v in row.items()} for row in cur.fetchall()]
