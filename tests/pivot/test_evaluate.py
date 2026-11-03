import json
import math

import numpy as np
import pytest

from attack_pivot.model import counting, evaluate as ev, smoothing, vcdb_diag
from attack_pivot.model.counting import Action, Edge, FlowGraph, Incident, Params
from attack_pivot.model.taxonomy import END, START, Taxonomy

TAX = Taxonomy(
    version="test",
    parent={f"T{i}": None for i in range(1, 7)},
    tactics={"T1": ["TA1"], "T2": ["TA1"], "T3": ["TA2"], "T4": ["TA2"], "T5": ["TA3"], "T6": ["TA3"]},
    tactic_order={"TA1": 1, "TA2": 2, "TA3": 3},
)  # fmt: skip


def chain(iid, *ts, date=None, classes=("independent",)):
    f = FlowGraph(
        iid,
        {str(i): Action(t) for i, t in enumerate(ts)},
        [Edge(str(i), str(i + 1)) for i in range(len(ts) - 1)],
    )
    return Incident(
        iid,
        counting.incident_transitions([f], Params(), TAX),
        date,
        classes,
        1,
        ("clear",),
    )


def corpus(n=24):
    """T1→T3→T5 mostly, T1→T4→T6 sometimes: a learnable pattern."""
    return [
        chain(
            f"i{k:02d}",
            *(("T1", "T3", "T5") if k % 3 else ("T1", "T4", "T6")),
            classes=("emulation",) if k < 4 else ("independent",),
        )
        for k in range(n)
    ]


def by_level(incidents):
    return {
        "technique": {i.id: i for i in incidents},
        "tactic": {
            i.id: Incident(
                i.id,
                counting.incident_transitions([_flow(i)], Params("tactic"), TAX),
                i.first_seen,
                i.source_classes,
            )
            for i in incidents
        },
    }


def _flow(inc):
    states = [b for (a, b) in inc.transitions if a != START and b != END]
    order = ["T1", "T3", "T4", "T5", "T6"]
    ts = [t for t in order if t in states or any(a == t for a, _ in inc.transitions)]
    return FlowGraph(
        inc.id,
        {str(i): Action(t) for i, t in enumerate(ts)},
        [Edge(str(i), str(i + 1)) for i in range(len(ts) - 1)],
    )


# ------------------------------------------------------------------ metrics
def test_metrics_with_ties_use_expected_rank():
    acc = ev.Accumulator(1)
    P = np.array([[0.25, 0.25, 0.25, 0.25]])
    acc.add("uniform", np.array([0]), np.array([1.0]), P, np.array([2]))
    num = acc.num["uniform"][0]
    hit1, hit5, _, mrr, loglik, brier = num
    assert hit1 == pytest.approx(0.25) and hit5 == pytest.approx(1.0)
    assert mrr == pytest.approx(
        (1 + 1 / 2 + 1 / 3 + 1 / 4) / 4
    )  # mean reciprocal over the tied positions
    assert loglik == pytest.approx(math.log(0.25))
    assert brier == pytest.approx(0.75**2 + 3 * 0.25**2)


def test_metrics_for_a_confident_correct_and_wrong_prediction():
    acc = ev.Accumulator(2)
    P = np.array([[0.7, 0.2, 0.1], [0.7, 0.2, 0.1]])
    acc.add("model", np.array([0, 1]), np.array([1.0, 1.0]), P, np.array([0, 2]))
    assert (
        acc.num["model"][0, 0] == 1 and acc.num["model"][1, 0] == 0
    )  # hit@1 per incident
    assert acc.num["model"][1, 3] == pytest.approx(1 / 3)  # rank 3
    assert acc.num["model"][0, 4] == pytest.approx(math.log(0.7))


def test_ece_matches_a_hand_computation():
    acc = ev.Accumulator(1)
    P = np.array([[0.9, 0.1], [0.9, 0.1]])
    acc.add("model", np.zeros(2, int), np.ones(2), P, np.array([0, 1]))
    # bin 0.9-1.0: n=2, Σp=1.8, Σy=1 -> 0.8; bin 0.1-0.2: n=2, Σp=0.2, Σy=1 -> 0.8; ECE = 1.6 / 4
    ece = ev._ece(acc.cal["model"].sum(axis=0))
    assert ece == pytest.approx(((abs(1.8 - 1) + abs(0.2 - 1)) / 4))
    floor = ev._ece(acc.cal_floor["model"].sum(axis=0))
    assert floor == pytest.approx(
        abs(1.8 - 1) / 2
    )  # only the p >= 0.05 predictions of the 0.9 bin... and 0.1 bin


# ---------------------------------------------------------------- baselines
def fitted(incidents, alpha=1.0):
    counts = {
        lv: counting.count(list(by_level(incidents)[lv].values()))
        for lv in ("technique", "tactic")
    }
    return smoothing.fit(counts, TAX, alpha, "technique")["technique"]


def test_baseline_matrices_are_distributions_with_the_expected_character():
    inc = corpus()
    model = fitted(inc)
    mats = ev.baseline_matrices(model, inc, TAX)
    assert set(mats) == set(ev.METHODS)
    for name, m in mats.items():
        assert m.shape == model.p.shape and np.allclose(m.sum(axis=1), 1), name
        assert (m > 0).all(), name
    j = model.dst_index
    t1 = model.src_index["T1"]
    # co-occurrence: T3 and T5 appear with T1 in 16/24 incidents more than T4/T6 (8/24)
    assert mats["cooccurrence"][t1, j["T3"]] > mats["cooccurrence"][t1, j["T4"]]
    # tactic order: T5 (TA3) follows T3 (TA2); T1 (TA1) does not follow T5
    s3, s5 = model.src_index["T3"], model.src_index["T5"]
    assert mats["tactic_order"][s3, j["T5"]] > mats["tactic_order"][s3, j["T1"]]
    assert mats["tactic_order"][s5, j["T1"]] < mats["tactic_order"][s5, j["T6"]]
    assert np.allclose(mats["uniform"], 1 / len(model.dests))


def test_model_beats_baselines_on_a_learnable_pattern():
    inc = corpus(60)
    level_inc = by_level(inc)
    ids = sorted(level_inc["technique"])
    rng = np.random.default_rng(0)
    order = list(rng.permutation(ids))
    parts = [set(order[i::5]) for i in range(5)]
    acc = ev.Accumulator(len(ids))
    ev.run_split(
        acc, 0, [set(ids) - p for p in parts], level_inc, "technique", TAX, 1.0, parts
    )
    out = ev.summarize(acc, np.random.default_rng(1), 300)
    assert out["n_incidents"] == 60
    model = out["methods"]["model"]
    assert model["hit@1"]["value"] > out["methods"]["uniform"]["hit@1"]["value"]
    for base in ("uniform", "tactic_order"):
        assert (
            out["vs_baseline"][base]["mrr"]["ci_excludes_zero"]
            and out["vs_baseline"][base]["mrr"]["model_better"]
        )
    assert out["vs_baseline"]["uniform"]["loglik"]["model_better"]
    lo, hi = model["mrr"]["ci"]
    assert lo <= model["mrr"]["value"] <= hi
    assert sum(b["n"] for b in out["reliability"]) > 0


def test_bootstrap_is_reproducible():
    inc = corpus(30)
    level_inc = by_level(inc)
    ids = sorted(level_inc["technique"])
    parts = [set(ids[i::5]) for i in range(5)]

    def run():
        acc = ev.Accumulator(len(ids))
        ev.run_split(
            acc,
            0,
            [set(ids) - p for p in parts],
            level_inc,
            "technique",
            TAX,
            1.0,
            parts,
        )
        return ev.summarize(acc, np.random.default_rng(7), 100)["methods"]["model"][
            "mrr"
        ]["ci"]

    assert run() == run()


def test_time_split_needs_enough_dated_incidents():
    inc = {i.id: i for i in corpus(24)}
    split, note = ev._time_split(inc)
    assert split is None and "only 0 of 24" in note
    dated = {
        k: Incident(k, v.transitions, f"2024-01-{n + 1:02d}", v.source_classes)
        for n, (k, v) in enumerate(inc.items())
    }
    (train, test, cutoff), note = ev._time_split(dated)
    assert note is None and train.isdisjoint(test) and len(train) + len(test) == 24
    assert all(
        dated[t].first_seen > cutoff >= dated[r].first_seen for t in test for r in train
    )
    assert len(test) in (4, 5)


def test_stability_leave_one_class_out():
    level_inc = by_level(corpus(30))
    res = ev.stability(level_inc, "technique", TAX, 1.0)
    assert set(res) == {"emulation", "independent"}
    assert res["emulation"]["rho"] > 0.9  # 4 of 30 incidents removed: same ranking
    assert res["emulation"]["left_out_incidents"] == 4


# -------------------------------------------------------------- VCDB diagnostic
def test_vcdb_tactic_counts_and_divergence():
    mapping = {
        "action.hacking.variety.Brute force": ["T1"],
        "action.malware.variety.Ransomware": ["T3", "T4"],
    }
    doc = {
        "action": {
            "hacking": {"variety": ["Brute force"]},
            "malware": {"variety": ["Ransomware"]},
        },
        "plus": {"event_chain": [{"action": "hak"}, {"action": "mal"}]},
    }
    unmappable = {**doc, "action": {"hacking": {"variety": ["Brute force"]}}}
    counts, used, skipped = vcdb_diag.tactic_counts(
        [doc, unmappable, {"plus": {}}], mapping, TAX
    )
    assert (used, skipped) == (1, 1)
    assert counts == {(START, "TA1"): 1, ("TA1", "TA2"): 1, ("TA2", END): 1}
    same = vcdb_diag.divergence(counts, dict(counts))
    assert same["joint"] == pytest.approx(0, abs=1e-9)
    far = vcdb_diag.divergence(counts, {(START, "TA3"): 3, ("TA3", END): 3})
    assert far["joint"] == pytest.approx(1.0, abs=1e-9)
    assert vcdb_diag.divergence({}, counts)["joint"] is None


# ---------------------------------------------------------------- end to end
@pytest.mark.pivot_db
def test_evaluate_run_writes_the_report(corpus_db, tmp_path):
    from attack_pivot.model import build

    run_id, _ = build.build_run(corpus_db, label="eval")
    path = ev.evaluate_run(
        corpus_db,
        run_id,
        seed=3,
        n_bootstrap=50,
        out_dir=tmp_path,
        alpha_sweep=(1.0, 20.0),
    )
    assert path.name == "report.md"
    text = path.read_text()
    for needle in (
        "Time-based split",
        "Not run — unavailable",
        "cross-validation",
        "α sweep",
        "Stability",
        "VCDB",
        "Go / no-go",
    ):
        assert needle in text, needle
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["incidents"] == 38 and set(report["alpha_sweep"]) == {"1.0", "20.0"}
    assert (tmp_path / "reliability.png").stat().st_size > 1000
    assert len(json.loads((tmp_path / "reliability.json").read_text())) == 10
    stored = corpus_db.execute(
        "SELECT eval FROM pivot.model_run WHERE id = %s", (run_id,)
    ).fetchone()["eval"]
    assert stored["cv5"]["n_incidents"] == 38
