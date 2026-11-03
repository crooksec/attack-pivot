"""Cluster incidents and manage the dedupe review queue (SPEC §5.5)."""

import logging
from collections import Counter, defaultdict

from psycopg.types.json import Jsonb

from attack_pivot.collect.text import canonical_url
from attack_pivot.dedupe import score as scoring

logger = logging.getLogger(__name__)


def load_features(conn):
    """One :class:`~attack_pivot.dedupe.score.Features` per incident that has a flow."""
    feats = {}
    for r in conn.execute(
        "SELECT id::text, first_seen, last_seen FROM pivot.incident i "
        "WHERE EXISTS (SELECT 1 FROM pivot.flow f WHERE f.incident_id = i.id)"
    ):
        feats[r["id"]] = scoring.Features(r["id"], r["first_seen"], r["last_seen"])
    for r in conn.execute(
        "SELECT f.incident_id::text AS i, fa.actor_id::text AS a FROM pivot.flow_actor fa "
        "JOIN pivot.flow f ON f.id = fa.flow_id WHERE f.incident_id IS NOT NULL"
    ):
        feats[r["i"]].actors.add(r["a"])
    for r in conn.execute(
        "SELECT f.incident_id::text AS i, a.technique_id AS t FROM pivot.action_obs a "
        "JOIN pivot.flow f ON f.id = a.flow_id WHERE a.technique_id IS NOT NULL AND f.incident_id IS NOT NULL"
    ):
        feats[r["i"]].techniques.add(r["t"])
    for r in conn.execute(
        "SELECT f.incident_id::text AS i, lower(t) AS t FROM pivot.flow_context c "
        "JOIN pivot.flow f ON f.id = c.flow_id, unnest(c.sectors || c.regions) AS t "
        "WHERE f.incident_id IS NOT NULL"
    ):
        feats[r["i"]].tags.add(r["t"])
    for r in conn.execute(
        "SELECT f.incident_id::text AS i, rep.url AS url, "
        "(SELECT jsonb_path_query_array(f.afb, '$.objects[*] ? (@.id == \"flow\").properties')) AS refs "
        "FROM pivot.flow f LEFT JOIN pivot.report rep ON rep.id = f.report_id "
        "WHERE f.incident_id IS NOT NULL"
    ):
        urls = scoring.urls_in(r["refs"]) | ({r["url"]} if r["url"] else set())
        feats[r["i"]].urls |= {canonical_url(u) for u in urls}
    return feats


def _existing_decisions(conn):
    return {
        (r["incident_a"], r["incident_b"]): r["status"]
        for r in conn.execute(
            "SELECT incident_a::text, incident_b::text, status FROM pivot.dedupe_candidate"
        )
    }


def _components(pairs):
    """Connected components over auto-link pairs: ``[(member_ids, min_score)]``."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b, *_ in pairs:
        parent[find(a)] = find(b)
    groups, floor = defaultdict(set), {}
    for a, b, s, *_ in pairs:
        root = find(a)
        groups[root] |= {a, b}
        floor[root] = min(floor.get(root, 1.0), s)
    return [(sorted(members), floor[root]) for root, members in groups.items()]


def merge_incidents(conn, ids, method, confidence):
    """
    Merge incidents into the one created first: move flows, transitions and report links, widen the
    date range, delete the emptied incidents. Every flow still belongs to exactly one incident.

    :return: The surviving incident id.
    """
    rows = conn.execute(
        "SELECT id::text FROM pivot.incident WHERE id = ANY(%s::uuid[]) ORDER BY created_at, id",
        (ids,),
    ).fetchall()
    keep, drop = rows[0]["id"], [r["id"] for r in rows[1:]]
    conn.execute(
        "UPDATE pivot.flow SET incident_id = %s WHERE incident_id = ANY(%s::uuid[])",
        (keep, drop),
    )
    conn.execute(
        "UPDATE pivot.transition_obs SET incident_id = %s WHERE incident_id = ANY(%s::uuid[])",
        (keep, drop),
    )
    conn.execute(
        "INSERT INTO pivot.report_incident (report_id, incident_id, link_confidence, method) "
        "SELECT report_id, %s, %s, %s FROM pivot.report_incident WHERE incident_id = ANY(%s::uuid[]) "
        "ON CONFLICT (report_id, incident_id) DO NOTHING",
        (keep, confidence, method, drop),
    )
    conn.execute(
        "UPDATE pivot.incident SET cluster_method = %s, cluster_confidence = %s, "
        "first_seen = (SELECT min(first_seen) FROM pivot.incident WHERE id = ANY(%s::uuid[])), "
        "last_seen = (SELECT max(last_seen) FROM pivot.incident WHERE id = ANY(%s::uuid[])) WHERE id = %s",
        (method, confidence, ids, ids, keep),
    )
    conn.execute("DELETE FROM pivot.incident WHERE id = ANY(%s::uuid[])", (drop,))
    return keep


def dedupe(conn, auto_only=False):
    """
    Score all incident pairs; auto-link those >= 0.75, queue 0.5-0.75 for review (unless
    ``auto_only``), leave the rest apart. Pairs a reviewer marked distinct are never linked.

    :return: Counter: ``incidents_before``, ``incidents_after``, ``auto_linked`` (merged groups),
        ``queued``, ``candidates``.
    """
    counts = Counter()
    features = list(load_features(conn).values())
    counts["incidents_before"] = len(features)
    decisions = _existing_decisions(conn)
    pairs = [
        p
        for p in scoring.candidates(features)
        if decisions.get(tuple(sorted(p[:2]))) != "distinct"
    ]
    counts["candidates"] = len(pairs)
    auto = [p for p in pairs if p[2] >= scoring.AUTO_LINK]
    for members, floor in _components(auto):
        merge_incidents(conn, members, "dedupe:auto", floor)
        counts["auto_linked"] += 1
    if not auto_only:
        survivors = {
            r["id"] for r in conn.execute("SELECT id::text FROM pivot.incident")
        }
        for a, b, s, signals in pairs:
            if s >= scoring.AUTO_LINK or a not in survivors or b not in survivors:
                continue
            conn.execute(
                "INSERT INTO pivot.dedupe_candidate (incident_a, incident_b, score, signals) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (incident_a, incident_b) DO UPDATE "
                "SET score = EXCLUDED.score, signals = EXCLUDED.signals WHERE dedupe_candidate.status = 'open'",
                (a, b, s, Jsonb(signals)),
            )
            counts["queued"] += 1
    counts["incidents_after"] = conn.execute(
        "SELECT count(*) AS n FROM pivot.incident"
    ).fetchone()["n"]
    conn.commit()
    return counts


def queue(conn, limit=None):
    """Open review items, highest score first, with both incidents' labels."""
    return conn.execute(
        "SELECT c.id::text, c.score, c.signals, ia.label AS label_a, ib.label AS label_b "
        "FROM pivot.dedupe_candidate c JOIN pivot.incident ia ON ia.id = c.incident_a "
        "JOIN pivot.incident ib ON ib.id = c.incident_b WHERE c.status = 'open' "
        "ORDER BY c.score DESC, c.id" + (" LIMIT %s" if limit else ""),
        (limit,) if limit else (),
    ).fetchall()


def resolve(conn, candidate_id, merge, by):
    """Merge the pair's incidents, or record that they are distinct (never proposed again)."""
    row = conn.execute(
        "SELECT incident_a::text AS a, incident_b::text AS b, score FROM pivot.dedupe_candidate "
        "WHERE id::text = %s AND status = 'open'",
        (candidate_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"no open review item {candidate_id!r}")
    if not by:
        raise RuntimeError("--by is required")
    if merge:
        merge_incidents(conn, [row["a"], row["b"]], "dedupe:review", 1.0)
    else:
        conn.execute(
            "UPDATE pivot.dedupe_candidate SET status = 'distinct', decided_by = %s, decided_at = now() "
            "WHERE id::text = %s",
            (by, candidate_id),
        )
    conn.commit()
