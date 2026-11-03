"""Model runs: fit, persist, snapshot the corpus, activate (SPEC §4 ``model_run``, §7)."""

import hashlib
import json
import logging
from collections import Counter

from psycopg.types.json import Jsonb

from attack_pivot.ingest.load import latest_attack_version
from attack_pivot.model import counting, smoothing
from attack_pivot.model.counting import DEFAULT_BASES, Params
from attack_pivot.model.taxonomy import END, START, Taxonomy

logger = logging.getLogger(__name__)
TOP_PRIOR = 20
HASH_DECIMALS = 10
LEVEL_CHAIN = {
    "subtechnique": ("subtechnique", "technique", "tactic"),
    "technique": ("technique", "tactic"),
    "tactic": ("tactic",),
}


def levels_for(level):
    """The level and its ancestors: all of them are fitted and stored in one run."""
    return LEVEL_CHAIN[level]


def estimates_hash(rows):
    """
    SHA-256 of the estimates, order-independent and rounded to :data:`HASH_DECIMALS` decimals,
    so the same inputs give the same hash.

    :param list[dict] rows: As returned by :func:`attack_pivot.model.smoothing.estimates`.
    """
    canon = [
        [r["level"], r["src"], r["dst"]]
        + [
            round(r[k], HASH_DECIMALS)
            for k in ("n_ab", "n_a", "p_mle", "p", "ci_low", "ci_high")
        ]
        for r in sorted(rows, key=lambda r: (r["level"], r["src"], r["dst"]))
    ]
    return hashlib.sha256(json.dumps(canon, separators=(",", ":")).encode()).hexdigest()


def corpus_snapshot(conn, incidents, counts):
    """
    Composition of the corpus a run was fitted on (``model_run.corpus_stats``).

    ``incident_level_transitions`` counts distinct (incident, a→b) with both ends real states
    (not START/END): the PRD's "ordered transitions" for the technique level.
    """
    real = {k: w for k, w in counts.n_ab.items() if START not in k and END not in k}
    ids = [i.id for i in incidents]
    bases = conn.execute(
        "SELECT t.order_basis, count(*) AS n FROM pivot.transition_obs t JOIN pivot.flow f ON f.id = t.flow_id "
        "WHERE f.incident_id = ANY(%s) GROUP BY 1 ORDER BY 1",
        (ids,),
    ).fetchall()
    dates = [str(i.first_seen) for i in incidents if i.first_seen]
    return {
        "incidents": len(incidents),
        "flows": sum(i.flows for i in incidents),
        "date_range": [min(dates), max(dates)] if dates else None,
        "incidents_without_date": sum(1 for i in incidents if not i.first_seen),
        "by_source_class": dict(
            Counter(c for i in incidents for c in (i.source_classes or ("unknown",)))
        ),
        "by_tlp": dict(Counter(t for i in incidents for t in (i.tlps or ("unknown",)))),
        "by_year": dict(
            sorted(
                Counter(
                    str(i.first_seen)[:4] for i in incidents if i.first_seen
                ).items()
            )
        ),
        "edges_by_order_basis": {r["order_basis"]: r["n"] for r in bases},
        "incident_level_transitions": round(sum(real.values()), 6),
        "unique_transition_pairs": len(real),
        "pairs_with_n_ge": {
            str(t): sum(1 for w in real.values() if w >= t) for t in (2, 5, 10)
        },
        "unique_states": len({s for pair in real for s in pair}),
    }


def build_run(
    conn,
    level="technique",
    alpha=1.0,
    bases=DEFAULT_BASES,
    fidelities=None,
    self_loops="keep",
    label=None,
    corpus_filter=None,
    attack_version=None,
    top_prior=TOP_PRIOR,
    activate=False,
):
    """
    Fit ``level`` and its ancestor levels on the current corpus and store the run.

    :return: ``(run_id, summary)``
    :rtype: tuple
    """
    version = attack_version or latest_attack_version(conn)
    if not version:
        raise RuntimeError(
            "no ATT&CK version in the database; run `afp attack sync` first"
        )
    taxonomy = Taxonomy.load(conn, version)
    corpus_filter = corpus_filter or {}

    incidents, counts = {}, {}
    for lv in levels_for(level):
        params = Params(
            lv, tuple(bases), tuple(fidelities) if fidelities else None, self_loops
        )
        incidents[lv] = counting.load_incidents(conn, params, taxonomy, corpus_filter)
        counts[lv] = counting.count(incidents[lv])
    if not incidents[level]:
        raise RuntimeError(
            "no incidents with ordered transitions match the corpus filter"
        )

    models = smoothing.fit(counts, taxonomy, alpha, level)
    rows = [
        r
        for lv in levels_for(level)
        for r in smoothing.estimates(models[lv], top_prior)
    ]
    digest = estimates_hash(rows)
    stats = corpus_snapshot(conn, incidents[level], counts[level])
    stats["incidents_by_level"] = {lv: len(incidents[lv]) for lv in incidents}
    params_doc = {
        "level": level,
        "stored_levels": list(levels_for(level)),
        "alpha": alpha,
        "allowed_bases": list(bases),
        "fidelities": list(fidelities) if fidelities else "level default",
        "self_loops": self_loops,
        "top_prior": top_prior,
        "ci": [smoothing.CI_LOW, smoothing.CI_HIGH],
    }
    run_id = conn.execute(
        "INSERT INTO pivot.model_run (label, attack_version, params, corpus_filter, corpus_stats, "
        "estimates_sha256) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (label, version, Jsonb(params_doc), Jsonb(corpus_filter), Jsonb(stats), digest),
    ).fetchone()["id"]
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO pivot.transition_estimate (run_id, level, src, dst, n_ab, n_a, p_mle, p, ci_low, ci_high) "
            "VALUES (%(run)s, %(level)s, %(src)s, %(dst)s, %(n_ab)s, %(n_a)s, %(p_mle)s, %(p)s, %(ci_low)s, %(ci_high)s)",
            [{**r, "run": run_id} for r in rows],
        )
    if activate:
        _activate(conn, run_id)
    conn.commit()
    return run_id, {"estimates": len(rows), "sha256": digest, "corpus": stats}


def _activate(conn, run_id):
    conn.execute(
        "UPDATE pivot.model_run SET is_active = false WHERE is_active AND id <> %s",
        (run_id,),
    )
    updated = conn.execute(
        "UPDATE pivot.model_run SET is_active = true WHERE id = %s", (run_id,)
    ).rowcount
    if not updated:
        raise RuntimeError(f"no model run {run_id}")


def activate(conn, run_id):
    """Make ``run_id`` the single active run."""
    _activate(conn, run_id)
    conn.commit()


def resolve_run(conn, ref):
    """
    Resolve a run reference (full id, unique id prefix, label or ``"active"``) to its id.

    :rtype: str
    """
    if ref == "active":
        row = conn.execute("SELECT id FROM pivot.model_run WHERE is_active").fetchone()
        if not row:
            raise RuntimeError("no active model run; run `afp model build --activate`")
        return row["id"]
    rows = conn.execute(
        "SELECT id FROM pivot.model_run WHERE id::text LIKE %s OR label = %s ORDER BY created_at DESC",
        (f"{ref}%", ref),
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError(
            f"run '{ref}' matches {len(rows)} runs" if rows else f"no model run '{ref}'"
        )
    return rows[0]["id"]


def list_runs(conn):
    """Runs, newest first, with their corpus size."""
    return conn.execute(
        "SELECT id, label, attack_version, is_active, created_at, estimates_sha256, "
        "(corpus_stats->>'incidents')::int AS incidents, params->>'level' AS level, params->>'alpha' AS alpha "
        "FROM pivot.model_run ORDER BY created_at DESC"
    ).fetchall()
