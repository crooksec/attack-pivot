"""``afp corpus stats``: what the corpus holds and how far it is from the M-Proof/M-Stretch targets."""

from attack_pivot.ingest.load import latest_attack_version
from attack_pivot.model import build, counting
from attack_pivot.model.taxonomy import Taxonomy
from attack_pivot.review import queue

MILESTONES = {
    "M-Proof": {"incidents": 500, "transitions": 5000},
    "M-Stretch": {"incidents": 2000, "transitions": 20000},
}


def _counter_rows(conn, sql):
    return {str(r["k"]): r["n"] for r in conn.execute(sql)}


def stats(conn, attack_version=None, corpus_filter=None):
    """
    Corpus composition and progress.

    Targets are measured on the technique-level model's default view: incidents that contribute at
    least one ordered transition, and incident-level ordered transitions (a pair counts at most
    once per incident). VCDB incidents with an event chain are a separate line and do not count
    toward the targets.

    :rtype: dict
    """
    version = attack_version or latest_attack_version(conn)
    if not version:
        raise RuntimeError(
            "no ATT&CK version in the database; run `afp attack sync` first"
        )
    params = counting.Params(level="technique")
    taxonomy = Taxonomy.load(conn, version)
    incidents = counting.load_incidents(conn, params, taxonomy, corpus_filter)
    counts = counting.count(incidents)
    snapshot = build.corpus_snapshot(conn, incidents, counts)

    contributing = sum(1 for i in incidents if i.transitions)
    transitions = snapshot["incident_level_transitions"]
    result = {
        "attack_version": version,
        **snapshot,
        "incidents_with_ordered_transitions": contributing,
        "reports": {
            "total": conn.execute("SELECT count(*) AS n FROM pivot.report").fetchone()[
                "n"
            ],
            "by_status": _counter_rows(
                conn,
                "SELECT triage_status AS k, count(*) AS n FROM pivot.report GROUP BY 1 ORDER BY 1",
            ),
            "by_source_class": _counter_rows(
                conn,
                "SELECT coalesce(s.source_class, 'unknown') AS k, count(*) AS n FROM pivot.report r "
                "LEFT JOIN pivot.source s ON s.id = r.source_id GROUP BY 1 ORDER BY 1",
            ),
            "by_tlp": _counter_rows(
                conn,
                "SELECT coalesce(tlp, 'unknown') AS k, count(*) AS n FROM pivot.report GROUP BY 1 ORDER BY 1",
            ),
            "by_year": _counter_rows(
                conn,
                "SELECT extract(year FROM published_at)::int AS k, count(*) AS n FROM pivot.report "
                "WHERE published_at IS NOT NULL GROUP BY 1 ORDER BY 1",
            ),
            "undated": conn.execute(
                "SELECT count(*) AS n FROM pivot.report WHERE published_at IS NULL"
            ).fetchone()["n"],
        },
        "flows_by_origin": _counter_rows(
            conn,
            "SELECT origin AS k, count(*) AS n FROM pivot.flow GROUP BY 1 ORDER BY 1",
        ),
        "flows_by_review_status": _counter_rows(
            conn,
            "SELECT review_status AS k, count(*) AS n FROM pivot.flow GROUP BY 1 ORDER BY 1",
        ),
        "unique_techniques": conn.execute(
            "SELECT count(DISTINCT a.technique_id) AS n FROM pivot.action_obs a JOIN pivot.flow f ON f.id = a.flow_id "
            "WHERE f.review_status <> 'rejected' AND a.technique_id IS NOT NULL"
        ).fetchone()["n"],
        "top_actors": [
            {"actor": r["name"], "incidents": r["n"]}
            for r in conn.execute(
                "SELECT a.name, count(DISTINCT f.incident_id) AS n FROM pivot.flow_actor fa "
                "JOIN pivot.actor a ON a.id = fa.actor_id JOIN pivot.flow f ON f.id = fa.flow_id "
                "WHERE f.review_status <> 'rejected' GROUP BY a.name ORDER BY n DESC, a.name LIMIT 10"
            )
        ],
        "review": queue.report(conn),
        "llm_calls": [
            {k: v for k, v in r.items()}
            for r in conn.execute(
                "SELECT purpose, count(*) AS calls, count(*) FILTER (WHERE NOT ok) AS failed, "
                "coalesce(sum(input_tokens), 0) AS input_tokens, coalesce(sum(output_tokens), 0) AS output_tokens "
                "FROM pivot.llm_call GROUP BY 1 ORDER BY 1"
            )
        ],
        "vcdb": conn.execute(
            "SELECT count(*) AS incidents, count(*) FILTER (WHERE has_sequence) AS with_sequence "
            "FROM pivot.veris_incident"
        ).fetchone(),
        "progress": {
            name: {
                "incidents": _progress(contributing, t["incidents"]),
                "transitions": _progress(transitions, t["transitions"]),
            }
            for name, t in MILESTONES.items()
        },
    }
    return result


def _progress(have, target):
    return {
        "have": round(have, 3),
        "target": target,
        "pct": round(100 * have / target, 1),
    }


def render(s):
    """Plain-text report."""

    def block(title, mapping):
        return [
            f"  {title}: "
            + (", ".join(f"{k}={v}" for k, v in mapping.items()) or "none")
        ]

    lines = [
        f"Corpus (ATT&CK {s['attack_version']})",
        f"  incidents {s['incidents']} ({s['incidents_with_ordered_transitions']} with ordered transitions), "
        f"flows {s['flows']}, reports {s['reports']['total']}",
        f"  incident-level ordered transitions {s['incident_level_transitions']}, unique pairs {s['unique_transition_pairs']}, "
        f"unique techniques {s['unique_techniques']}",
        f"  pairs with n >= 2/5/10: {s['pairs_with_n_ge']['2']}/{s['pairs_with_n_ge']['5']}/{s['pairs_with_n_ge']['10']}",
        f"  dates: {' to '.join(s['date_range']) if s['date_range'] else 'none'}, incidents without a date {s['incidents_without_date']}",
        *block("incidents by source class", s["by_source_class"]),
        *block("incidents by TLP", s["by_tlp"]),
        *block("incidents by year", s["by_year"]),
        *block("edges by order_basis", s["edges_by_order_basis"]),
        *block("reports by status", s["reports"]["by_status"]),
        *block("flows by origin", s["flows_by_origin"]),
        *block("flows by review status", s["flows_by_review_status"]),
        "  top actors: "
        + (
            ", ".join(f"{a['actor']} ({a['incidents']})" for a in s["top_actors"][:5])
            or "none"
        ),
    ]
    r = s["review"]
    lines.append(
        f"  review: {r['reviewed_flows']}/{r['reviewed_flows_needed']} flows reviewed, "
        + (
            f"edge precision {r['both_correct']:.1%} over {r['edges']} edges (target {r['target']:.0%})"
            if r.get("edges")
            else "no edges reviewed yet"
        )
    )
    v = s["vcdb"]
    lines.append(
        f"  VCDB (separate, not counted toward targets): {v['incidents']} incidents, {v['with_sequence']} with an event chain"
    )
    for name, p in s["progress"].items():
        lines.append(
            f"  {name}: incidents {p['incidents']['have']:g}/{p['incidents']['target']} ({p['incidents']['pct']}%), "
            f"transitions {p['transitions']['have']:g}/{p['transitions']['target']} ({p['transitions']['pct']}%)"
        )
    return "\n".join(lines)
