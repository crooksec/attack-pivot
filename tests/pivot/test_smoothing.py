from fractions import Fraction as F

import numpy as np
import pytest
from scipy.stats import beta

from attack_pivot.model import counting, smoothing
from attack_pivot.model.counting import Action, Edge, FlowGraph, Incident, Params
from attack_pivot.model.taxonomy import END, START, Taxonomy

TAX = Taxonomy(
    version="test",
    parent={"T1": None, "T2": None, "T3": None},
    tactics={"T1": ["TA1"], "T2": ["TA1"], "T3": ["TA2"]},
    tactic_order={"TA1": 1, "TA2": 2},
)
SUB = Taxonomy(
    version="test",
    parent={"T1": None, "T1.001": "T1", "T1.002": "T1", "T3": None},
    tactics={"T1": ["TA1"], "T1.001": ["TA1"], "T1.002": ["TA1"], "T3": ["TA2"]},
    tactic_order={"TA1": 1, "TA2": 2},
)


def chain(incident, *techniques):
    actions = {str(i): Action(t) for i, t in enumerate(techniques)}
    edges = [Edge(str(i), str(i + 1)) for i in range(len(techniques) - 1)]
    return FlowGraph(incident, actions, edges)


def counts_for(taxonomy, flows, level):
    params = Params(level=level)
    incs = [
        Incident(f.incident_id, counting.incident_transitions([f], params, taxonomy))
        for f in flows
    ]
    return counting.count(incs)


def fit(taxonomy, flows, level, alpha=1.0):
    by_level = {}
    lv = level
    while lv:
        by_level[lv] = counts_for(taxonomy, flows, lv)
        lv = smoothing.LEVEL_PARENT[lv]
    return smoothing.fit(by_level, taxonomy, alpha, level)


FLOWS = [chain("i1", "T1", "T3"), chain("i2", "T1", "T2")]


def test_tactic_level_matches_hand_computation():
    m = smoothing.fit_level("tactic", counts_for(TAX, FLOWS, "tactic"), TAX, 1.0)
    row = lambda a: dict(zip(m.dests, m.p[m.src_index[a]]))  # noqa: E731
    # destination popularity (3, 1, 2 of 6) with add-one over 3 columns: 4/9, 2/9, 3/9
    expect = {
        START: {"TA1": F(22, 27), "TA2": F(2, 27), END: F(1, 9)},
        "TA1": {"TA1": F(13, 36), "TA2": F(11, 36), END: F(1, 3)},
        "TA2": {"TA1": F(2, 9), "TA2": F(1, 9), END: F(2, 3)},
    }
    for a, dist in expect.items():
        for b, value in dist.items():
            assert row(a)[b] == pytest.approx(float(value), abs=1e-9), (a, b)


def test_technique_level_matches_hand_computation():
    models = fit(TAX, FLOWS, "technique")
    m = models["technique"]
    p = lambda a, b: m.p[m.src_index[a], m.dst_index[b]]  # noqa: E731
    assert p("T1", "T3") == pytest.approx(47 / 108, abs=1e-9)
    assert p("T1", "T2") == pytest.approx(103 / 270, abs=1e-9)
    assert p("T1", "T1") == pytest.approx(13 / 180, abs=1e-9)
    assert p("T1", END) == pytest.approx(1 / 9, abs=1e-9)
    assert (m.n_ab[m.src_index["T1"], m.dst_index["T3"]], m.n_a[m.src_index["T1"]]) == (
        1,
        2,
    )


def test_rows_are_distributions_and_unseen_sources_fall_back_to_the_prior():
    cases = (
        ("technique", TAX, [chain("i1", "T1", "T3")], "T2"),
        ("subtechnique", SUB, [chain("i1", "T1.001", "T3")], "T1.002"),
    )
    for level, taxonomy, flows, unseen in cases:
        m = fit(taxonomy, flows, level)[level]
        assert np.allclose(m.p.sum(axis=1), 1) and np.allclose(m.q.sum(axis=1), 1)
        assert (m.p > 0).all()
        row = m.src_index[unseen]
        assert m.n_a[row] == 0
        assert np.allclose(m.p[row], m.q[row])  # n_a = 0 -> p = q


def test_credible_interval_is_the_beta_marginal():
    m = fit(TAX, FLOWS, "technique")["technique"]
    i, j = m.src_index["T1"], m.dst_index["T3"]
    low, high = m.interval()
    q = m.q[i, j]
    a, b = 1 + 1.0 * q, (2 - 1) + 1.0 * (1 - q)
    assert low[i, j] == pytest.approx(beta.ppf(0.05, a, b), abs=1e-12)
    assert high[i, j] == pytest.approx(beta.ppf(0.95, a, b), abs=1e-12)
    assert (low <= m.p).all() and (m.p <= high).all()


def test_interval_narrows_with_more_data():
    few = fit(TAX, [chain("i1", "T1", "T3")], "technique")["technique"]
    many = fit(TAX, [chain(f"i{k}", "T1", "T3") for k in range(40)], "technique")[
        "technique"
    ]

    def width(m):
        low, high = m.interval()
        i, j = m.src_index["T1"], m.dst_index["T3"]
        return high[i, j] - low[i, j]

    assert width(many) < width(few) / 2


def test_alpha_controls_pull_to_the_prior():
    weak = fit(TAX, FLOWS, "technique", alpha=0.1)["technique"]
    strong = fit(TAX, FLOWS, "technique", alpha=50)["technique"]
    i, j = weak.src_index["T1"], weak.dst_index["T3"]
    assert abs(strong.p[i, j] - strong.q[i, j]) < abs(weak.p[i, j] - weak.q[i, j])


def reference_subtechnique(taxonomy, models, counts, alpha=F(1)):
    """Straight-line Fraction re-implementation of the sub-technique prior, for cross-checking."""
    tech = models["technique"]
    vocab = taxonomy.vocabulary("subtechnique")
    dests = [*vocab, END]
    marginal = {d: F(0) for d in dests}
    for (a, b), w in counts.n_ab.items():
        marginal[b] += F(w).limit_denominator(10**6)
    groups = {}
    for d in vocab:
        groups.setdefault(taxonomy.technique_parent(d), []).append(d)
    out = {}
    for a in [START, *vocab]:
        pa = a if a == START else taxonomy.technique_parent(a)
        n_a = sum(
            F(w).limit_denominator(10**6) for (x, _), w in counts.n_ab.items() if x == a
        )
        q = {}
        for g, members in groups.items():
            total = sum(marginal[x] for x in members) + len(members)
            for b in members:
                pg = F(
                    float(tech.p[tech.src_index[pa], tech.dst_index[g]])
                ).limit_denominator(10**12)
                q[b] = pg * (marginal[b] + 1) / total
        q[END] = F(
            float(tech.p[tech.src_index[pa], tech.dst_index[END]])
        ).limit_denominator(10**12)
        norm = sum(q.values())
        for b in dests:
            n_ab = F(counts.n_ab.get((a, b), 0)).limit_denominator(10**6)
            out[(a, b)] = (n_ab + alpha * q[b] / norm) / (n_a + alpha)
    return out


def test_subtechnique_level_matches_an_independent_reference():
    flows = [
        chain("i1", "T1.001", "T3"),
        chain("i2", "T1.002", "T1.001"),
        chain("i3", "T1.001", "T3"),
    ]
    models = smoothing.fit(
        {
            lv: counts_for(SUB, flows, lv)
            for lv in ("subtechnique", "technique", "tactic")
        },
        SUB,
        1.0,
        "subtechnique",
    )
    m = models["subtechnique"]
    ref = reference_subtechnique(SUB, models, counts_for(SUB, flows, "subtechnique"))
    for (a, b), value in ref.items():
        assert m.p[m.src_index[a], m.dst_index[b]] == pytest.approx(
            float(value), abs=1e-9
        ), (a, b)


def test_empty_data_gives_uniform_tactic_popularity():
    m = smoothing.fit_level("tactic", counting.count([]), TAX, 1.0)
    assert np.allclose(m.q, 1 / 3) and np.allclose(m.p, 1 / 3)


def test_estimates_rows_include_observed_and_top_prior_only():
    m = fit(TAX, FLOWS, "technique")["technique"]
    rows = smoothing.estimates(m, top_prior=1)
    t1 = [r for r in rows if r["src"] == "T1"]
    assert {r["dst"] for r in t1 if r["n_ab"] > 0} == {"T3", "T2"}
    prior = [r for r in t1 if r["n_ab"] == 0]
    assert len(prior) == 1 and prior[0]["p"] == max(
        m.p[m.src_index["T1"], m.dst_index[d]] for d in ("T1", END)
    )
    for r in rows:
        assert r["ci_low"] <= r["p"] <= r["ci_high"] and r["n_a"] > 0
        assert r["p_mle"] == pytest.approx(r["n_ab"] / r["n_a"])
    assert all(
        r["src"] != "T3" or r["n_a"] == 1 for r in rows
    )  # sources are the observed ones
