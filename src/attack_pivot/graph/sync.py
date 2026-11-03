"""Materialize the AGE graph from the relational tables (SPEC §8.1).

The graph is derived and fully rebuildable: ``sync`` deletes every vertex and edge with Cypher
and recreates them. It never drops the graph itself (AGE's drop function cascades), because AGE keeps the graph's tables in the
``pivot`` schema, the same schema as the relational source of truth.
"""

import logging

from attack_pivot.graph.age import cypher
from attack_pivot.ingest.load import latest_attack_version

logger = logging.getLogger(__name__)
GRAPH = "pivot"

VERTEX_LABELS = [
    "Technique", "Tactic", "Group", "Incident", "Flow", "Report", "Source", "Analytic",
    "VerisIncident", "State",
]  # fmt: skip
EDGE_LABELS = [
    "SUBTECHNIQUE_OF", "IN_TACTIC", "OBSERVED", "PART_OF", "REPORTED_IN", "PUBLISHED_BY",
    "ATTRIBUTED_TO", "DETECTABLE_BY", "CODED_AS",
]  # fmt: skip


def _ensure_labels(conn):
    existing = {
        r["name"]
        for r in conn.execute(
            "SELECT l.name FROM ag_catalog.ag_label l JOIN ag_catalog.ag_graph g "
            "ON g.graphid = l.graph WHERE g.name = %s",
            (GRAPH,),
        )
    }
    for label in VERTEX_LABELS:
        if label not in existing:
            conn.execute("SELECT ag_catalog.create_vlabel(%s, %s)", (GRAPH, label))
    for label in EDGE_LABELS:
        if label not in existing:
            conn.execute("SELECT ag_catalog.create_elabel(%s, %s)", (GRAPH, label))


def clear(conn):
    """Delete every vertex and edge (never drop the graph; see the module docstring)."""
    cypher(conn, "MATCH (n) DETACH DELETE n")


def _flat(label):
    return f"UNWIND $rows AS r CREATE (n:{label}) SET n = r"


def _create_vertices(conn, label, rows):
    if rows:
        cypher(conn, _flat(label), {"rows": rows})
    return len(rows)


def _create_edges(conn, label, src_label, src_key, dst_label, dst_key, rows, props=()):
    """
    Create ``(src)-[:label]->(dst)`` for rows ``{src, dst, <props>}``.

    Endpoints are matched on their identity property; rows whose endpoints are missing are
    dropped by the MATCH. Edge properties are set one by one (AGE's ``SET e = map`` only accepts
    a literal map or a bare parameter, not ``r.props``) and backticked, because names such as
    ``count`` are Cypher keywords.
    """
    if not rows:
        return 0
    sets = "".join(f" SET e.`{p}` = r.`{p}`" for p in props)
    cypher(
        conn,
        f"UNWIND $rows AS r MATCH (a:{src_label} {{{src_key}: r.src}}), "
        f"(b:{dst_label} {{{dst_key}: r.dst}}) CREATE (a)-[e:{label}]->(b){sets}",
        {"rows": rows},
    )
    return len(rows)


def _s(value):
    return None if value is None else str(value)


def _clean(row):
    """AGE properties cannot hold NULL map values on SET; drop them."""
    return {k: v for k, v in row.items() if v is not None}


def sync(conn, attack_version=None):
    """
    Rebuild the graph's structural vertices and edges.

    ``NEXT`` edges arrive with the model (P1). Software, Mitigation, DataComponent, D3FEND
    vertices and their edges are not built: the relational schema (SPEC §4) has no tables for them.

    :param psycopg.Connection conn:
    :param str attack_version: Defaults to the latest synced ATT&CK version.
    :return: Counts of vertices and edges created, keyed by label.
    :rtype: dict
    """
    version = attack_version or latest_attack_version(conn)
    if not version:
        raise RuntimeError(
            "no ATT&CK version in the database; run `afp attack sync` first"
        )
    _ensure_labels(conn)
    clear(conn)
    q = lambda sql, *a: conn.execute(sql, a).fetchall()  # noqa: E731
    counts = {}

    techniques = q(
        "SELECT attack_id, name, parent_id, tactic_ids FROM pivot.technique "
        "WHERE version = %s AND NOT revoked AND NOT deprecated",
        version,
    )
    tactics = q(
        "SELECT attack_id, name, ord FROM pivot.tactic WHERE version = %s", version
    )
    groups = q(
        "SELECT attack_group_id, name FROM pivot.actor WHERE attack_group_id IS NOT NULL"
    )
    incidents = q("SELECT id, label, first_seen FROM pivot.incident")
    flows = q("SELECT id, name, origin, tlp, incident_id, report_id FROM pivot.flow")
    reports = q("SELECT id, url, published_at, tlp, source_id FROM pivot.report")
    sources = q("SELECT id, name, source_class, reliability FROM pivot.source")
    analytics = q("SELECT id, title, information_domain FROM pivot.analytic")
    veris = q("SELECT id, victim_industry, year, flow_id FROM pivot.veris_incident")

    counts["Technique"] = _create_vertices(
        conn,
        "Technique",
        [
            _clean({"attack_id": t["attack_id"], "name": t["name"], "parent_id": t["parent_id"],
                    "tactics": t["tactic_ids"] or []})
            for t in techniques
        ],
    )  # fmt: skip
    counts["Tactic"] = _create_vertices(conn, "Tactic", [_clean(t) for t in tactics])
    counts["Group"] = _create_vertices(conn, "Group", [_clean(g) for g in groups])
    counts["Incident"] = _create_vertices(
        conn,
        "Incident",
        [
            _clean(
                {
                    "id": _s(i["id"]),
                    "label": i["label"],
                    "first_seen": _s(i["first_seen"]),
                }
            )
            for i in incidents
        ],
    )
    counts["Flow"] = _create_vertices(
        conn,
        "Flow",
        [
            _clean(
                {
                    "id": _s(f["id"]),
                    "name": f["name"],
                    "origin": f["origin"],
                    "tlp": f["tlp"],
                }
            )
            for f in flows
        ],
    )
    counts["Report"] = _create_vertices(
        conn,
        "Report",
        [
            _clean(
                {
                    "id": _s(r["id"]),
                    "url": r["url"],
                    "published_at": _s(r["published_at"]),
                    "tlp": r["tlp"],
                }
            )
            for r in reports
        ],
    )
    counts["Source"] = _create_vertices(
        conn,
        "Source",
        [
            _clean(
                {
                    "id": _s(s["id"]),
                    "name": s["name"],
                    "source_class": s["source_class"],
                    "reliability": s["reliability"],
                }
            )
            for s in sources
        ],
    )
    counts["Analytic"] = _create_vertices(
        conn, "Analytic", [_clean(a) for a in analytics]
    )
    counts["VerisIncident"] = _create_vertices(
        conn,
        "VerisIncident",
        [
            _clean({"id": v["id"], "industry": v["victim_industry"], "year": v["year"]})
            for v in veris
        ],
    )
    counts["State"] = _create_vertices(
        conn, "State", [{"name": "START"}, {"name": "END"}]
    )

    ids = {t["attack_id"] for t in techniques}
    sub = [
        {"src": t["attack_id"], "dst": t["parent_id"]}
        for t in techniques
        if t["parent_id"] in ids
    ]
    counts["SUBTECHNIQUE_OF"] = _create_edges(
        conn, "SUBTECHNIQUE_OF", "Technique", "attack_id", "Technique", "attack_id", sub
    )
    in_tactic = [
        {"src": t["attack_id"], "dst": tac}
        for t in techniques
        for tac in (t["tactic_ids"] or [])
    ]
    counts["IN_TACTIC"] = _create_edges(
        conn, "IN_TACTIC", "Technique", "attack_id", "Tactic", "attack_id", in_tactic
    )

    observed = q(
        "SELECT f.id AS flow, a.technique_id AS technique, count(*) AS n FROM pivot.action_obs a "
        "JOIN pivot.flow f ON f.id = a.flow_id WHERE a.technique_id = ANY(%s) GROUP BY 1, 2",
        sorted(ids),
    )
    counts["OBSERVED"] = _create_edges(
        conn, "OBSERVED", "Flow", "id", "Technique", "attack_id",
        [{"src": str(r["flow"]), "dst": r["technique"], "count": r["n"]} for r in observed],
        props=("count",),
    )  # fmt: skip
    counts["PART_OF"] = _create_edges(
        conn, "PART_OF", "Flow", "id", "Incident", "id",
        [{"src": str(f["id"]), "dst": str(f["incident_id"])} for f in flows if f["incident_id"]],
    )  # fmt: skip
    counts["REPORTED_IN"] = _create_edges(
        conn, "REPORTED_IN", "Flow", "id", "Report", "id",
        [{"src": str(f["id"]), "dst": str(f["report_id"])} for f in flows if f["report_id"]],
    )  # fmt: skip
    counts["PUBLISHED_BY"] = _create_edges(
        conn, "PUBLISHED_BY", "Report", "id", "Source", "id",
        [{"src": str(r["id"]), "dst": str(r["source_id"])} for r in reports if r["source_id"]],
    )  # fmt: skip
    attributed = q(
        "SELECT f.incident_id AS incident, a.attack_group_id AS grp, max(fa.attribution_confidence) AS conf "
        "FROM pivot.flow_actor fa JOIN pivot.flow f ON f.id = fa.flow_id "
        "JOIN pivot.actor a ON a.id = fa.actor_id "
        "WHERE a.attack_group_id IS NOT NULL AND f.incident_id IS NOT NULL GROUP BY 1, 2"
    )
    counts["ATTRIBUTED_TO"] = _create_edges(
        conn, "ATTRIBUTED_TO", "Incident", "id", "Group", "attack_group_id",
        [{"src": str(r["incident"]), "dst": r["grp"], "confidence": r["conf"]} for r in attributed],
        props=("confidence",),
    )  # fmt: skip
    detectable = q(
        "SELECT technique_id, analytic_id, coverage FROM pivot.analytic_technique "
        "WHERE technique_id = ANY(%s)",
        sorted(ids),
    )
    counts["DETECTABLE_BY"] = _create_edges(
        conn, "DETECTABLE_BY", "Technique", "attack_id", "Analytic", "id",
        [{"src": r["technique_id"], "dst": r["analytic_id"], "coverage": r["coverage"]} for r in detectable],
        props=("coverage",),
    )  # fmt: skip
    counts["CODED_AS"] = _create_edges(
        conn, "CODED_AS", "Incident", "id", "VerisIncident", "id",
        [
            {"src": str(r["incident"]), "dst": r["id"]}
            for r in q(
                "SELECT v.id, f.incident_id AS incident FROM pivot.veris_incident v "
                "JOIN pivot.flow f ON f.id = v.flow_id WHERE f.incident_id IS NOT NULL"
            )
        ],
    )  # fmt: skip
    conn.commit()
    return counts
