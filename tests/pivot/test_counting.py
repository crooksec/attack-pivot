import re
from pathlib import Path

import pytest

from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.ingest import load
from attack_pivot.ingest.afb import parse_afb_file
from attack_pivot.model import counting
from attack_pivot.model.counting import Action, Edge, FlowGraph, Incident, Params
from attack_pivot.model.taxonomy import END, START, Taxonomy

ROOT = Path(__file__).resolve().parents[2]
CORPUS = sorted((ROOT / "corpus").glob("*.afb"))

TAX = Taxonomy(
    version="test",
    parent={"T1": None, "T1.001": "T1", "T1.002": "T1", "T2": None, "T3": None, "T4": None},
    tactics={"T1": ["TA1"], "T1.001": ["TA1"], "T1.002": ["TA1"], "T2": ["TA1", "TA2"], "T3": ["TA2"], "T4": ["TA1"]},
    tactic_order={"TA1": 1, "TA2": 2, "TA3": 3},
)  # fmt: skip


def acts(**kw):
    return {
        k: Action(*(v if isinstance(v, tuple) else (v, None))) for k, v in kw.items()
    }


def flow(actions, *edges, incident="i1"):
    return FlowGraph(
        incident, actions, [Edge(*e) if isinstance(e, tuple) else e for e in edges]
    )


def trans(flows, **params):
    return counting.incident_transitions(flows, Params(**params), TAX)


def test_chain_gets_start_and_end():
    f = flow(acts(a="T1", b="T2", c="T3"), ("a", "b"), ("b", "c"))
    assert trans([f]) == {
        (START, "T1"): 1,
        ("T1", "T2"): 1,
        ("T2", "T3"): 1,
        ("T3", END): 1,
    }


def test_branch_has_one_start_and_two_ends():
    f = flow(acts(a="T1", b="T2", c="T3"), ("a", "b"), ("a", "c"))
    assert set(trans([f])) == {
        (START, "T1"),
        ("T1", "T2"),
        ("T1", "T3"),
        ("T2", END),
        ("T3", END),
    }


def test_transition_counts_once_per_incident_and_across_its_flows():
    twice = flow(acts(a="T1", b="T2", c="T1", d="T2"), ("a", "b"), ("c", "d"))
    other_flow = flow(acts(x="T1", y="T2"), ("x", "y"))
    assert trans([twice, other_flow])[("T1", "T2")] == 1


def test_count_sums_over_incidents():
    f = lambda i: Incident(
        i, trans([flow(acts(a="T1", b="T2"), ("a", "b"))])
    )  # noqa: E731
    counts = counting.count([f("i1"), f("i2"), f("i3")])
    assert counts.incidents == 3
    assert counts.n_ab[("T1", "T2")] == 3 and counts.n_ab[(START, "T1")] == 3
    assert counts.n_a["T1"] == 3  # T1 -> T2 only
    other = Incident("i4", trans([flow(acts(a="T1", b="T3"), ("a", "b"))]))
    assert counting.count([f("i1"), other]).n_a["T1"] == 2  # Σ_b n_ab


def test_level_roll_up():
    f = flow(acts(a="T1.001", b="T1.002"), ("a", "b"))
    assert ("T1.001", "T1.002") in trans([f], level="subtechnique")
    assert trans([f], level="technique") == {
        (START, "T1"): 1,
        ("T1", "T1"): 1,
        ("T1", END): 1,
    }
    assert ("T1", "T1") not in trans([f], level="technique", self_loops="drop")


def test_order_basis_filter_and_flows_with_no_eligible_edge():
    llm = flow(acts(a="T1", b="T2"), ("a", "b", "inferred_llm"))
    assert trans([llm]) == {}  # no START/END from an excluded edge
    assert trans([llm], allowed_bases=("inferred_llm",))[("T1", "T2")] == 1
    mixed = flow(acts(a="T1", b="T2", c="T3"), ("a", "b"), ("b", "c", "inferred_llm"))
    # b has an (excluded) out-edge so no END; c is reachable only through an excluded edge so no END
    assert trans([mixed]) == {(START, "T1"): 1, ("T1", "T2"): 1}


def test_unlabeled_actions_are_dropped_but_still_block_start_and_end():
    f = flow(acts(a="T1", u=None, b="T2"), ("a", "u"), ("u", "b"))
    # no labeled pair; a is a source and b a sink, but nothing says a precedes b directly
    assert trans([f]) == {(START, "T1"): 1, ("T2", END): 1}
    g = flow(acts(a="T1", u=None, b="T2", c="T3"), ("a", "u"), ("u", "b"), ("b", "c"))
    assert trans([g]) == {(START, "T1"): 1, ("T2", "T3"): 1, ("T3", END): 1}
    h = flow(acts(u=None, b="T2", c="T3"), ("u", "b"), ("b", "c"))
    assert (START, "T2") not in trans([h])  # b's predecessor is unlabeled, not absent


def test_isolated_actions_get_no_start_or_end():
    f = flow(acts(a="T1", b="T2", lone="T3"), ("a", "b"))
    assert not any("T3" in pair for pair in trans([f]))


def test_tactic_level_splits_multi_tactic_techniques_and_uses_tactic_only_actions():
    f = flow(acts(a="T1", b="T2", c=(None, "TA3")), ("a", "b"), ("b", "c"))
    got = trans([f], level="tactic")
    assert (
        got[("TA1", "TA1")] == 0.5 and got[("TA1", "TA2")] == 0.5
    )  # T1(TA1) -> T2(TA1|TA2)
    assert got[("TA1", "TA3")] == 0.5 and got[("TA2", "TA3")] == 0.5
    assert got[(START, "TA1")] == 1 and got[("TA3", END)] == 1


def test_fractional_contributions_are_capped_at_one_per_incident():
    f = flow(acts(a="T2", b="T4", c="T4", d="T4"), ("a", "b"), ("c", "d"))
    # T2 -> T4 gives (TA1,TA1) 0.5; T4 -> T4 gives (TA1,TA1) 1.0; sum 1.5 -> 1
    assert trans([f], level="tactic")[("TA1", "TA1")] == 1


def test_fidelity_filter_by_level():
    coarse = flow(
        acts(a="T1", b="T3"), Edge("a", "b", "mapped_sequence", "mapped_coarse")
    )
    bases = ("mapped_sequence",)
    assert (
        trans([coarse], allowed_bases=bases) == {}
    )  # excluded from the technique-level model
    assert ("TA1", "TA2") in trans([coarse], allowed_bases=bases, level="tactic")
    assert ("T1", "T3") in trans(
        [coarse], allowed_bases=bases, fidelities=("mapped_coarse",)
    )


def test_unknown_technique_has_no_state():
    f = flow(acts(a="T999", b="T2"), ("a", "b"))
    assert trans([f]) == {("T2", END): 1}  # T999 is treated like an unlabeled action


# ------------------------------------------------------------------ database loader
pytestmark_db = pytest.mark.pivot_db


def _seed(conn):
    """ATT&CK 'test' knowing every Enterprise-style corpus ID, with a tactic each."""
    ids = {
        a.technique_id
        for p in CORPUS
        for a in parse_afb_file(p).actions
        if a.technique_id and re.fullmatch(r"T\d{4}(\.\d{3})?", a.technique_id)
    }
    conn.execute(
        "INSERT INTO pivot.attack_version (version, released) VALUES ('test', '2026-10-13')"
    )
    conn.execute(
        "INSERT INTO pivot.tactic (attack_id, version, name, ord) VALUES ('TA0001', 'test', 'x', 1)"
    )
    for tid in sorted(ids):
        conn.execute(
            "INSERT INTO pivot.technique (attack_id, version, name, parent_id, tactic_ids) VALUES (%s, 'test', %s, %s, %s)",
            (tid, tid, tid.split(".")[0] if "." in tid else None, ["TA0001"]),
        )
    conn.commit()
    return ids


@pytest.mark.pivot_db
def test_load_incidents_from_the_seed_corpus(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        _seed(conn)
        load.ingest_paths(conn, CORPUS, version="test")
        tax = Taxonomy.load(conn, "test")
        incidents = counting.load_incidents(conn, Params(), tax)
        names = {i.id for i in incidents}
        # Example Attack Tree (unordered) and the two OpenClaw flows (ATLAS only) give nothing
        assert len(incidents) == 38 and len(names) == 38
        counts = counting.count(incidents)
        assert counts.incidents == 38
        assert all(0 < w <= 1 for i in incidents for w in i.transitions.values())
        assert counts.n_a[START] == counts.n_ab[(START, "T1566")] + sum(
            w for (a, b), w in counts.n_ab.items() if a == START and b != "T1566"
        )
        # filtering
        only_emulation = counting.load_incidents(
            conn, Params(), tax, {"source_class": ["emulation"]}
        )
        assert len(only_emulation) == 2
        none = counting.load_incidents(conn, Params(), tax, {"tlp": ["red"]})
        assert none == []
