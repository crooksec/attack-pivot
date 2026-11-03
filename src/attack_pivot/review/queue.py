"""Sampling, reviewing and scoring extracted flows (SPEC §6.5, PRD §5.4)."""

import math
import random
from collections import defaultdict

from psycopg.types.json import Jsonb

ORDER_BASES = {
    "explicit",
    "timestamp",
    "inferred_narrative",
    "unordered",
    "inferred_llm",
}
TARGET = 0.85  # PRD §5.4
MIN_FLOWS = 50
MIN_FRACTION = 0.10


def sample(conn, batch, fraction=0.10, cap=50, seed=0):
    """
    Pick flows for review: unreviewed, LLM-extracted, not yet in a batch, with at least one edge.
    Size = min(ceil(fraction × eligible), cap), allocated across source classes in proportion to
    their share (at least one each where the size allows), drawn with a seeded RNG, and tagged
    with ``batch``.

    :return: The sampled flow ids.
    """
    if conn.execute(
        "SELECT 1 FROM pivot.flow WHERE review_batch = %s LIMIT 1", (batch,)
    ).fetchone():
        raise RuntimeError(f"batch {batch!r} already exists")
    rows = conn.execute(
        "SELECT f.id::text AS id, coalesce(s.source_class, 'other') AS cls FROM pivot.flow f "
        "LEFT JOIN pivot.report r ON r.id = f.report_id LEFT JOIN pivot.source s ON s.id = r.source_id "
        "WHERE f.origin = 'llm' AND f.review_status = 'unreviewed' AND f.review_batch IS NULL "
        "AND EXISTS (SELECT 1 FROM pivot.transition_obs t WHERE t.flow_id = f.id) ORDER BY f.id"
    ).fetchall()
    if not rows:
        return []
    size = min(math.ceil(fraction * len(rows)), cap)
    strata = defaultdict(list)
    for r in rows:
        strata[r["cls"]].append(r["id"])
    rng = random.Random(seed)
    quota = {c: max(1, round(size * len(v) / len(rows))) for c, v in strata.items()}
    chosen = []
    for cls in sorted(strata):
        pool = strata[cls][:]
        rng.shuffle(pool)
        chosen += pool[: quota[cls]]
    rng.shuffle(chosen)
    chosen = chosen[:size]
    conn.execute(
        "UPDATE pivot.flow SET review_batch = %s WHERE id::text = ANY(%s)",
        (batch, chosen),
    )
    conn.commit()
    return chosen


def pending(conn, batch):
    return conn.execute(
        "SELECT f.id::text AS id, f.name, r.url, s.source_class, "
        "(SELECT count(*) FROM pivot.transition_obs t WHERE t.flow_id = f.id) AS edges "
        "FROM pivot.flow f LEFT JOIN pivot.report r ON r.id = f.report_id "
        "LEFT JOIN pivot.source s ON s.id = r.source_id "
        "WHERE f.review_batch = %s AND f.review_status = 'unreviewed' ORDER BY f.id",
        (batch,),
    ).fetchall()


def show(conn, flow_id):
    """A flow's header and numbered edges, for the reviewer. Never returns report text."""
    flow = conn.execute(
        "SELECT f.id::text AS id, f.name, f.review_status, r.url, r.title FROM pivot.flow f "
        "LEFT JOIN pivot.report r ON r.id = f.report_id WHERE f.id::text = %s",
        (flow_id,),
    ).fetchone()
    if flow is None:
        raise RuntimeError(f"no flow {flow_id!r}")
    edges = conn.execute(
        "SELECT t.id::text AS id, sa.name AS src_name, da.name AS dst_name, t.src_technique, "
        "t.dst_technique, t.order_basis, t.via, t.evidence_quote FROM pivot.transition_obs t "
        "JOIN pivot.action_obs sa ON sa.id = t.src_action JOIN pivot.action_obs da ON da.id = t.dst_action "
        "WHERE t.flow_id::text = %s ORDER BY sa.node_ref, da.node_ref, t.via",
        (flow_id,),
    ).fetchall()
    return flow, edges


def _edge(conn, flow_id, edge_id):
    row = conn.execute(
        "SELECT t.id, t.src_action, t.dst_action, t.src_technique, t.dst_technique, t.order_basis, "
        "t.delta_seconds FROM pivot.transition_obs t WHERE t.flow_id::text = %s AND t.id::text LIKE %s",
        (flow_id, f"{edge_id}%"),
    ).fetchall()
    if len(row) != 1:
        raise RuntimeError(f"edge {edge_id!r} is not one edge of flow {flow_id}")
    return row[0]


def _unreviewed(conn, flow_id, by):
    if not by:
        raise RuntimeError("--by is required")
    row = conn.execute(
        "SELECT review_status, origin FROM pivot.flow WHERE id::text = %s", (flow_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"no flow {flow_id!r}")
    if row["review_status"] != "unreviewed":
        raise RuntimeError(f"flow {flow_id} is already {row['review_status']}")


def _log(conn, flow_id, verdict, original, by):
    conn.execute(
        "INSERT INTO pivot.review_edge (flow_id, verdict, original, reviewer) VALUES (%s, %s, %s, %s)",
        (flow_id, verdict, Jsonb(original), by),
    )


def _original(e):
    return {
        "src": e["src_technique"],
        "dst": e["dst_technique"],
        "order_basis": e["order_basis"],
    }


def _finish(conn, flow_id, status, by):
    conn.execute(
        "UPDATE pivot.flow SET review_status = %s, reviewer = %s, reviewed_at = now() WHERE id::text = %s",
        (status, by, flow_id),
    )
    conn.commit()


def accept(conn, flow_id, by):
    """Every edge of the flow is correct (direction and order_basis)."""
    _unreviewed(conn, flow_id, by)
    for e in conn.execute(
        "SELECT src_technique, dst_technique, order_basis FROM pivot.transition_obs WHERE flow_id::text = %s",
        (flow_id,),
    ).fetchall():
        _log(conn, flow_id, "correct", _original(e), by)
    _finish(conn, flow_id, "accepted", by)


def correct(conn, flow_id, by, flip=(), delete=(), basis=None, add=()):
    """
    Apply a reviewer's corrections; every other edge counts as correct.

    :param flip: Edge ids whose direction is reversed.
    :param delete: Edge ids that should not exist.
    :param dict basis: ``{edge id: new order_basis}``.
    :param add: ``(src_action_ref, dst_action_ref, order_basis)`` edges the extraction missed;
        refs are the flow's ``node_ref`` values.
    """
    _unreviewed(conn, flow_id, by)
    basis = basis or {}
    for value in basis.values():
        if value not in ORDER_BASES:
            raise RuntimeError(f"unknown order_basis {value!r}")
    if set(delete) & (set(flip) | set(basis)):
        raise RuntimeError("an edge cannot be both deleted and edited")
    touched = {}
    for edge_id in {*flip, *delete, *basis}:
        touched[edge_id] = _edge(conn, flow_id, edge_id)
    seen = set()
    for edge_id, e in touched.items():
        if e["id"] in seen:
            raise RuntimeError(f"edge {edge_id!r} given twice")
        seen.add(e["id"])
        if edge_id in delete:
            _log(conn, flow_id, "spurious", _original(e), by)
            conn.execute("DELETE FROM pivot.transition_obs WHERE id = %s", (e["id"],))
            continue
        flipped, rebased = edge_id in flip, edge_id in basis
        _log(
            conn,
            flow_id,
            {
                (True, True): "flipped_and_basis_changed",
                (True, False): "flipped",
                (False, True): "basis_changed",
            }[(flipped, rebased)],
            _original(e),
            by,
        )
        conn.execute(
            "UPDATE pivot.transition_obs SET src_action = %s, dst_action = %s, src_technique = %s, "
            "dst_technique = %s, order_basis = %s, delta_seconds = %s WHERE id = %s",
            (
                e["dst_action"] if flipped else e["src_action"],
                e["src_action"] if flipped else e["dst_action"],
                e["dst_technique"] if flipped else e["src_technique"],
                e["src_technique"] if flipped else e["dst_technique"],
                basis.get(edge_id, e["order_basis"]),
                (
                    -e["delta_seconds"]
                    if flipped and e["delta_seconds"] is not None
                    else e["delta_seconds"]
                ),
                e["id"],
            ),
        )
    added = []
    for src_ref, dst_ref, order_basis in add:
        if order_basis not in ORDER_BASES:
            raise RuntimeError(f"unknown order_basis {order_basis!r}")
        acts = {
            a["node_ref"]: a
            for a in conn.execute(
                "SELECT id, node_ref, technique_id FROM pivot.action_obs WHERE flow_id::text = %s",
                (flow_id,),
            )
        }
        if src_ref not in acts or dst_ref not in acts:
            raise RuntimeError(
                f"no action {src_ref!r} or {dst_ref!r} in flow {flow_id}"
            )
        inc = conn.execute(
            "SELECT incident_id FROM pivot.flow WHERE id::text = %s", (flow_id,)
        ).fetchone()["incident_id"]
        new = conn.execute(
            "INSERT INTO pivot.transition_obs (flow_id, incident_id, src_action, dst_action, src_technique, "
            "dst_technique, order_basis, via) VALUES (%s, %s, %s, %s, %s, %s, %s, 'direct') RETURNING id",
            (
                flow_id,
                inc,
                acts[src_ref]["id"],
                acts[dst_ref]["id"],
                acts[src_ref]["technique_id"],
                acts[dst_ref]["technique_id"],
                order_basis,
            ),
        )
        added.append(new.fetchone()["id"])
        _log(
            conn,
            flow_id,
            "missed",
            {
                "src": acts[src_ref]["technique_id"],
                "dst": acts[dst_ref]["technique_id"],
                "order_basis": order_basis,
            },
            by,
        )
    untouched = conn.execute(
        "SELECT src_technique, dst_technique, order_basis FROM pivot.transition_obs "
        "WHERE flow_id::text = %s AND NOT (id = ANY(%s::uuid[]))",
        (flow_id, [e["id"] for e in touched.values()] + added),
    ).fetchall()
    for e in untouched:
        _log(conn, flow_id, "correct", _original(e), by)
    _finish(conn, flow_id, "corrected", by)


def reject(conn, flow_id, by):
    """The flow is unusable: all its edges count as wrong and the model ignores it."""
    _unreviewed(conn, flow_id, by)
    for e in conn.execute(
        "SELECT src_technique, dst_technique, order_basis FROM pivot.transition_obs WHERE flow_id::text = %s",
        (flow_id,),
    ).fetchall():
        _log(conn, flow_id, "spurious", _original(e), by)
    _finish(conn, flow_id, "rejected", by)


def report(conn, batch=None):
    """
    Precision of reviewed edges (PRD §5.4): the share with the correct direction *and*
    ``order_basis``, plus direction-only and basis-only rates and coverage of the review target.

    :rtype: dict
    """
    where, params = ("AND f.review_batch = %s", (batch,)) if batch else ("", ())
    verdicts = {
        (r["cls"], r["verdict"]): r["n"]
        for r in conn.execute(
            "SELECT coalesce(s.source_class, 'other') AS cls, e.verdict, count(*) AS n FROM pivot.review_edge e "
            "JOIN pivot.flow f ON f.id = e.flow_id LEFT JOIN pivot.report r ON r.id = f.report_id "
            "LEFT JOIN pivot.source s ON s.id = r.source_id WHERE true "
            + where
            + " GROUP BY 1, 2",
            params,
        )
    }

    def rates(items):
        n = lambda *v: sum(c for (k, vv), c in items if vv in v)  # noqa: E731
        reviewed = n(
            "correct",
            "flipped",
            "basis_changed",
            "flipped_and_basis_changed",
            "spurious",
        )
        if not reviewed:
            return {"edges": 0}
        return {
            "edges": reviewed,
            "both_correct": n("correct") / reviewed,
            "direction_correct": n("correct", "basis_changed") / reviewed,
            "basis_correct": n("correct", "flipped") / reviewed,
            "spurious": n("spurious"),
            "missed": n("missed"),
        }

    overall = rates(list(verdicts.items()))
    by_class = defaultdict(list)
    for (cls, v), c in verdicts.items():
        by_class[cls].append(((cls, v), c))
    flows = conn.execute(
        "SELECT count(*) FILTER (WHERE origin = 'llm') AS llm, "
        "count(*) FILTER (WHERE origin = 'llm' AND review_status <> 'unreviewed') AS reviewed "
        "FROM pivot.flow"
    ).fetchone()
    need = max(MIN_FLOWS, math.ceil(MIN_FRACTION * flows["llm"]))
    return {
        **overall,
        "target": TARGET,
        "passes": overall.get("edges", 0) > 0
        and overall["both_correct"] >= TARGET
        and flows["reviewed"] >= need,
        "llm_flows": flows["llm"],
        "reviewed_flows": flows["reviewed"],
        "reviewed_flows_needed": need,
        "by_source_class": {c: rates(v) for c, v in sorted(by_class.items())},
    }
