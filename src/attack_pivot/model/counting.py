"""Incident-level transition counting (SPEC §7.1–7.2).

Pure functions over plain data, so they are testable without a database. The database side is
:func:`load_incidents`.
"""

from collections import defaultdict
from dataclasses import dataclass, field

from attack_pivot.model.taxonomy import END, START

DEFAULT_BASES = ("explicit", "timestamp", "inferred_narrative")
# mapped_coarse (VERIS-derived) is excluded from the technique-level model and included at tactic level.
DEFAULT_FIDELITIES = {
    "subtechnique": ("technique",),
    "technique": ("technique",),
    "tactic": ("technique", "mapped_coarse"),
}


@dataclass(frozen=True)
class Params:
    """Counting parameters (stored in ``model_run.params``)."""

    level: str = "technique"
    allowed_bases: tuple = DEFAULT_BASES
    fidelities: tuple | None = None  # None: the level's default
    self_loops: str = "keep"  # keep | drop

    def allowed_fidelities(self):
        return self.fidelities or DEFAULT_FIDELITIES[self.level]


@dataclass
class Action:
    technique_id: str | None = None
    tactic_id: str | None = None


@dataclass
class Edge:
    src: str
    dst: str
    order_basis: str = "explicit"
    fidelity: str = "technique"


@dataclass
class FlowGraph:
    """One flow's action graph. ``actions`` maps action id → :class:`Action`."""

    incident_id: str
    actions: dict
    edges: list = field(default_factory=list)


@dataclass
class Incident:
    """One incident's contribution: its transitions with weights in ``(0, 1]``."""

    id: str
    transitions: dict  # (src state, dst state) -> weight
    first_seen: object = None
    source_classes: tuple = ()
    flows: int = 0
    tlps: tuple = ()


def flow_transitions(flow, params, taxonomy):
    """
    Weighted state transitions of one flow, including ``START → a`` and ``b → END``.

    Unlabeled actions have no state and are dropped, but degrees are taken on the full action
    graph, so an action whose only predecessor is unlabeled does not get a ``START``. A flow
    contributes only if it has at least one edge passing the ``order_basis`` and ``fidelity``
    filters. ``START`` / ``END`` need an eligible edge at the action: an action with no edges, or
    reachable only through excluded (e.g. LLM-inferred) edges, carries no trusted ordering and
    gets neither.

    :rtype: dict[tuple[str, str], float]
    """
    eligible = [
        e
        for e in flow.edges
        if e.order_basis in params.allowed_bases
        and e.fidelity in params.allowed_fidelities()
    ]
    if not eligible:
        return {}
    states = {
        aid: taxonomy.states(params.level, a.technique_id, a.tactic_id)
        for aid, a in flow.actions.items()
    }
    has_in = {e.dst for e in flow.edges}
    has_out = {e.src for e in flow.edges}
    good_in = {e.dst for e in eligible}
    good_out = {e.src for e in eligible}
    pairs = defaultdict(float)

    def add(src_states, dst_states):
        for s, ws in src_states:
            for d, wd in dst_states:
                if params.self_loops == "drop" and s == d:
                    continue
                pairs[(s, d)] += ws * wd

    for e in eligible:
        add(states.get(e.src, []), states.get(e.dst, []))
    for aid, st in states.items():
        if aid in good_out and aid not in has_in:
            add([(START, 1.0)], st)
        if aid in good_in and aid not in has_out:
            add(st, [(END, 1.0)])
    return dict(pairs)


def incident_transitions(flows, params, taxonomy):
    """
    Merge the flows of one incident: a transition counts at most once per incident (its weight
    is the sum over the incident's flows and events, capped at 1).

    :rtype: dict[tuple[str, str], float]
    """
    merged = defaultdict(float)
    for flow in flows:
        for pair, weight in flow_transitions(flow, params, taxonomy).items():
            merged[pair] += weight
    return {pair: min(1.0, w) for pair, w in merged.items()}


@dataclass
class Counts:
    """Counts over a set of incidents: ``n_ab[(a, b)]`` and ``n_a[a] = Σ_b n_ab``."""

    n_ab: dict
    n_a: dict
    incidents: int


def count(incidents):
    """
    Sum incident-level transitions.

    :param list[Incident] incidents:
    :rtype: Counts
    """
    n_ab, n_a = defaultdict(float), defaultdict(float)
    for incident in incidents:
        for (a, b), w in incident.transitions.items():
            n_ab[(a, b)] += w
            n_a[a] += w
    return Counts(dict(n_ab), dict(n_a), len(incidents))


def load_incidents(conn, params, taxonomy, corpus_filter=None):
    """
    Read flows from the database and group them into :class:`Incident` objects.

    Rejected flows are excluded. ``corpus_filter`` may restrict ``tlp`` (list),
    ``source_class`` (list), ``from_date`` / ``to_date`` (by incident ``first_seen``).

    :rtype: list[Incident]
    """
    corpus_filter = corpus_filter or {}
    flows = conn.execute(
        "SELECT f.id AS flow_id, f.incident_id, i.first_seen, s.source_class, f.tlp "
        "FROM pivot.flow f JOIN pivot.incident i ON i.id = f.incident_id "
        "LEFT JOIN pivot.report r ON r.id = f.report_id LEFT JOIN pivot.source s ON s.id = r.source_id "
        "WHERE f.review_status <> 'rejected' ORDER BY f.incident_id, f.id"
    ).fetchall()
    keep = []
    for f in flows:
        if corpus_filter.get("tlp") and f["tlp"] not in corpus_filter["tlp"]:
            continue
        if (
            corpus_filter.get("source_class")
            and f["source_class"] not in corpus_filter["source_class"]
        ):
            continue
        date = f["first_seen"]
        if (
            date
            and corpus_filter.get("from_date")
            and str(date) < corpus_filter["from_date"]
        ):
            continue
        if (
            date
            and corpus_filter.get("to_date")
            and str(date) > corpus_filter["to_date"]
        ):
            continue
        keep.append(f)
    flow_ids = [f["flow_id"] for f in keep]
    actions = defaultdict(dict)
    for a in conn.execute(
        "SELECT flow_id, id, technique_id, tactic_id FROM pivot.action_obs WHERE flow_id = ANY(%s)",
        (flow_ids,),
    ):
        actions[a["flow_id"]][a["id"]] = Action(a["technique_id"], a["tactic_id"])
    edges = defaultdict(list)
    for t in conn.execute(
        "SELECT flow_id, src_action, dst_action, order_basis, fidelity FROM pivot.transition_obs "
        "WHERE flow_id = ANY(%s)",
        (flow_ids,),
    ):
        edges[t["flow_id"]].append(
            Edge(t["src_action"], t["dst_action"], t["order_basis"], t["fidelity"])
        )

    by_incident = defaultdict(list)
    meta = {}
    for f in keep:
        by_incident[f["incident_id"]].append(
            FlowGraph(f["incident_id"], actions[f["flow_id"]], edges[f["flow_id"]])
        )
        m = meta.setdefault(
            f["incident_id"],
            {
                "first_seen": f["first_seen"],
                "classes": set(),
                "tlps": set(),
                "flows": 0,
            },
        )
        m["classes"].add(f["source_class"])
        m["tlps"].add(f["tlp"])
        m["flows"] += 1
    incidents = []
    for iid, graphs in by_incident.items():
        transitions = incident_transitions(graphs, params, taxonomy)
        if transitions:
            incidents.append(
                Incident(
                    str(iid),
                    transitions,
                    meta[iid]["first_seen"],
                    tuple(sorted(c for c in meta[iid]["classes"] if c)),
                    meta[iid]["flows"],
                    tuple(sorted(t for t in meta[iid]["tlps"] if t)),
                )
            )
    return sorted(incidents, key=lambda i: i.id)
