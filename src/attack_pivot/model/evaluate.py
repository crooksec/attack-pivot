"""Evaluation harness (SPEC §7.4): splits, baselines, metrics, bootstrap, stability, VCDB diagnostic.

Task: for each held-out transition ``a → b`` (``a`` is not START) rank every candidate
destination by the model's probability of following ``a``. Baselines are scored with the same
metrics; each yields a full probability row per source so log-likelihood, Brier and calibration
are defined for all of them. Ties are broken at random in expectation (a uniform model gets the
mid-rank, not a free hit).
"""

import json
import logging
import os
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

from attack_pivot.model import counting, smoothing
from attack_pivot.model.build import levels_for
from attack_pivot.model.counting import Params
from attack_pivot.model.taxonomy import END, START, Taxonomy

logger = logging.getLogger(__name__)

METHODS = ("model", "uniform", "popularity", "cooccurrence", "tactic_order")
METRICS = ("hit@1", "hit@5", "hit@10", "mrr", "loglik", "brier")
LOWER_IS_BETTER = {"brier", "ece"}
N_BINS = 10
ECE_FLOOR = 0.05  # PRD §5: ECE over bins with p >= 0.05
MIN_DATED_FOR_TIME_SPLIT = 20
CHUNK = 2000


# ------------------------------------------------------------------------- baselines
def _normalise(scores):
    return scores / scores.sum(axis=1, keepdims=True)


def baseline_matrices(model, train, taxonomy):
    """
    Probability matrices (same shape as ``model.p``) for the four baselines, from training data.

    - uniform: every destination equally likely;
    - popularity: add-one marginal of the destination;
    - co-occurrence (TIE-style, unordered): share of training incidents containing ``a`` that
      also contain ``b`` (``b = a`` scored 0, END by its popularity), floored at 1e-3 and
      normalised; unseen sources fall back to popularity;
    - tactic-order prior: destinations whose latest tactic is not before the source's earliest
      tactic score 1, the rest 0.1 (END follows everything, START precedes everything).
    """
    n_src, n_dst = len(model.sources), len(model.dests)
    marginal = model.n_ab.sum(axis=0)
    popularity = (marginal + 1.0) / (marginal.sum() + n_dst)
    pop = np.tile(popularity, (n_src, 1))
    uniform = np.full((n_src, n_dst), 1.0 / n_dst)

    containing = defaultdict(set)
    for k, inc in enumerate(train):
        for a, b in inc.transitions:
            for s in (a, b):
                if s not in (START, END):
                    containing[s].add(k)
    cooc = pop.copy()
    end_share = popularity[model.dst_index[END]]
    for a, members in containing.items():
        i = model.src_index.get(a)
        if i is None:
            continue
        row = np.zeros(n_dst)
        for b, j in model.dst_index.items():
            if b == END:
                row[j] = end_share
            elif b != a and b in containing:
                row[j] = len(members & containing[b]) / len(members)
        cooc[i] = (row + 1e-3) / (row + 1e-3).sum()

    def first(state):
        tactics = taxonomy.tactics.get(state) or (
            [state] if state in taxonomy.tactic_order else []
        )
        return min((taxonomy.tactic_order.get(t, 0) for t in tactics), default=0)

    def last(state):
        tactics = taxonomy.tactics.get(state) or (
            [state] if state in taxonomy.tactic_order else []
        )
        return max((taxonomy.tactic_order.get(t, 0) for t in tactics), default=0)

    order = np.full((n_src, n_dst), 0.1)
    for a, i in model.src_index.items():
        ord_a = -1 if a == START else first(a)
        for b, j in model.dst_index.items():
            if b == END or last(b) >= ord_a:
                order[i, j] = 1.0
    return {
        "model": model.p,
        "uniform": uniform,
        "popularity": pop,
        "cooccurrence": cooc,
        "tactic_order": _normalise(order),
    }


# --------------------------------------------------------------------------- scoring
_HARMONIC = np.concatenate([[0.0], np.cumsum(1.0 / np.arange(1, 20001))])


def _harmonic(n):
    n = np.asarray(n)
    return _HARMONIC[np.minimum(n, len(_HARMONIC) - 1)]


class Accumulator:
    """Per-incident sums of every metric and calibration bin, pooled over folds."""

    def __init__(self, n_incidents):
        self.den = np.zeros(n_incidents)
        self.num = {m: np.zeros((n_incidents, len(METRICS))) for m in METHODS}
        self.cal = {m: np.zeros((n_incidents, N_BINS, 3)) for m in METHODS}  # n, Σp, Σy
        self.cal_floor = {m: np.zeros((n_incidents, N_BINS, 3)) for m in METHODS}
        self.transitions = 0

    def add(self, method, inc, w, P, b):
        t = np.arange(len(b))
        ptrue = P[t, b]
        greater = (P > ptrue[:, None]).sum(axis=1)
        ties = (P == ptrue[:, None]).sum(axis=1)
        values = [np.clip((k - greater) / ties, 0, 1) for k in (1, 5, 10)] + [
            (_harmonic(greater + ties) - _harmonic(greater)) / ties,
            np.log(np.maximum(ptrue, 1e-300)),
            (P**2).sum(axis=1) - 2 * ptrue + 1,
        ]
        n_inc = self.den.shape[0]
        for k, v in enumerate(values):
            self.num[method][:, k] += np.bincount(inc, w * v, minlength=n_inc)
        bins = np.minimum((P * N_BINS).astype(int), N_BINS - 1)
        flat = (inc[:, None] * N_BINS + bins).ravel()
        wf = np.repeat(w, P.shape[1])
        for store, mask in ((self.cal, None), (self.cal_floor, P.ravel() >= ECE_FLOOR)):
            f, ww, pp = (
                (flat, wf, P.ravel())
                if mask is None
                else (flat[mask], wf[mask], P.ravel()[mask])
            )
            n = np.bincount(f, ww, minlength=n_inc * N_BINS)
            sp = np.bincount(f, ww * pp, minlength=n_inc * N_BINS)
            true_flat = inc * N_BINS + bins[t, b]
            keep = np.ones(len(b), bool) if mask is None else ptrue >= ECE_FLOOR
            sy = np.bincount(true_flat[keep], w[keep], minlength=n_inc * N_BINS)
            store[method][:] += np.stack([n, sp, sy], axis=1).reshape(n_inc, N_BINS, 3)


def _ece(cal):
    """Expected calibration error from ``(..., bins, [n, Σp, Σy])`` sums."""
    n = cal[..., 0].sum(axis=-1)
    gap = np.abs(cal[..., 1] - cal[..., 2]).sum(axis=-1)
    return np.where(n > 0, gap / np.where(n > 0, n, 1), np.nan)


def run_split(
    accum, offset, folds, level_inc, top_level, taxonomy, alpha, test_ids_by_fold
):
    """
    Fit on each fold's training incidents, score its held-out transitions into ``accum``.

    :param level_inc: ``{level: {incident id: Incident}}``.
    :param folds: list of training id sets, aligned with ``test_ids_by_fold``.
    :return: next free incident offset.
    """
    for train_ids, test_ids in zip(folds, test_ids_by_fold):
        counts = {
            lv: counting.count([i for k, i in level_inc[lv].items() if k in train_ids])
            for lv in level_inc
        }
        models = smoothing.fit(counts, taxonomy, alpha, top_level)
        model = models[top_level]
        train = [
            level_inc[top_level][k] for k in train_ids if k in level_inc[top_level]
        ]
        matrices = baseline_matrices(model, train, taxonomy)
        incs, ws, srcs, dsts = [], [], [], []
        for n, iid in enumerate(sorted(test_ids)):
            for (a, b), w in level_inc[top_level][iid].transitions.items():
                if a == START or a not in model.src_index or b not in model.dst_index:
                    continue
                incs.append(offset + n)
                ws.append(w)
                srcs.append(model.src_index[a])
                dsts.append(model.dst_index[b])
        incs, ws, srcs, dsts = map(np.array, (incs, ws, srcs, dsts))
        if len(ws):
            accum.den += np.bincount(incs, ws, minlength=accum.den.shape[0])
            accum.transitions += len(ws)
            for lo in range(0, len(ws), CHUNK):
                s = slice(lo, lo + CHUNK)
                for name, matrix in matrices.items():
                    accum.add(name, incs[s], ws[s], matrix[srcs[s]], dsts[s])
        offset += len(test_ids)
    return offset


def summarize(accum, rng, n_bootstrap):
    """Metric values, bootstrap CIs (resampling test incidents) and model-vs-baseline differences."""
    n_inc = accum.den.shape[0]
    valid = accum.den > 0
    den, num = accum.den[valid], {m: accum.num[m][valid] for m in METHODS}
    cal = {m: accum.cal[m][valid] for m in METHODS}
    cal_floor = {m: accum.cal_floor[m][valid] for m in METHODS}
    n = int(valid.sum())
    out = {
        "n_incidents": n,
        "n_transitions": accum.transitions,
        "methods": {},
        "vs_baseline": {},
    }
    if n == 0:
        return out
    counts = rng.multinomial(n, np.full(n, 1.0 / n), size=n_bootstrap).astype(float)
    boot_den = counts @ den

    def values(method, c=None):
        w = None if c is None else c
        d = den.sum() if c is None else boot_den
        nm = num[method].sum(axis=0) if c is None else c @ num[method]
        res = {k: nm[..., i] / d for i, k in enumerate(METRICS)}
        for key, store in (("ece", cal), ("ece_p>=0.05", cal_floor)):
            tot = (
                store[method].sum(axis=0)
                if c is None
                else np.einsum("bi,ijk->bjk", c, store[method])
            )
            res[key] = _ece(tot)
        return res

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # empty ECE bins for baselines
        point = {m: values(m) for m in METHODS}
        boot = {m: values(m, counts) for m in METHODS}
        return _finish(out, point, boot, cal, n)


def _finish(out, point, boot, cal, n):
    for m in METHODS:
        out["methods"][m] = {
            k: {
                "value": float(point[m][k]),
                "ci": [
                    float(np.nanpercentile(boot[m][k], 2.5)),
                    float(np.nanpercentile(boot[m][k], 97.5)),
                ],
            }
            for k in point[m]
        }
    for base in METHODS[1:]:
        out["vs_baseline"][base] = {}
        for k in point["model"]:
            diff = boot["model"][k] - boot[base][k]
            lo, hi = float(np.nanpercentile(diff, 2.5)), float(
                np.nanpercentile(diff, 97.5)
            )
            d = float(point["model"][k] - point[base][k])
            better = d < 0 if k in LOWER_IS_BETTER else d > 0
            out["vs_baseline"][base][k] = {
                "diff": d,
                "ci": [lo, hi],
                "ci_excludes_zero": bool(lo > 0 or hi < 0),
                "model_better": bool(better),
            }
    total = cal["model"].sum(axis=0)
    out["reliability"] = [
        {
            "bin": [i / N_BINS, (i + 1) / N_BINS],
            "n": float(total[i, 0]),
            "mean_p": float(total[i, 1] / total[i, 0]) if total[i, 0] else None,
            "observed": float(total[i, 2] / total[i, 0]) if total[i, 0] else None,
        }
        for i in range(N_BINS)
    ]
    return out


# ------------------------------------------------------------------------- stability
def stability(level_inc, top_level, taxonomy, alpha, top_n=200):
    """
    Leave-one-source-class-out: Spearman ρ between the full model's probabilities of its top
    ``top_n`` observed transitions and the same transitions under a model trained without the class.
    """
    incidents = level_inc[top_level]
    classes = sorted({c for i in incidents.values() for c in i.source_classes})
    ids = set(incidents)

    def fit_on(keep):
        counts = {
            lv: counting.count([i for k, i in level_inc[lv].items() if k in keep])
            for lv in level_inc
        }
        return smoothing.fit(counts, taxonomy, alpha, top_level)[top_level]

    full = fit_on(ids)
    observed = np.argwhere((full.n_ab > 0) & (np.array(full.sources)[:, None] != START))
    scores = sorted(((full.p[i, j], i, j) for i, j in observed), reverse=True)[:top_n]
    results = {}
    for c in classes:
        keep = {k for k, i in incidents.items() if c not in i.source_classes}
        if not keep or len(keep) == len(ids) or len(scores) < 3:
            results[c] = {
                "rho": None,
                "note": "class covers every incident or too few transitions",
            }
            continue
        part = fit_on(keep)
        a = [full.p[i, j] for _, i, j in scores]
        b = [part.p[i, j] for _, i, j in scores]
        rho = spearmanr(a, b).statistic
        results[c] = {
            "rho": None if np.isnan(rho) else float(rho),
            "left_out_incidents": len(ids) - len(keep),
            "transitions": len(scores),
        }
    return results


# ---------------------------------------------------------------------------- driver
def _time_split(incidents):
    dated = sorted(
        (str(i.first_seen), i.id) for i in incidents.values() if i.first_seen
    )
    if len(dated) < MIN_DATED_FOR_TIME_SPLIT:
        return (
            None,
            f"unavailable: only {len(dated)} of {len(incidents)} incidents have a date (need {MIN_DATED_FOR_TIME_SPLIT})",
        )
    cutoff = dated[int(0.8 * len(dated)) - 1][0]
    train = {k for d, k in dated if d <= cutoff}
    test = {k for d, k in dated if d > cutoff}
    if not test:
        return None, "unavailable: no incident after the 80th-percentile cutoff"
    return (train, test, cutoff), None


def evaluate_run(
    conn, run_id, seed=0, n_bootstrap=1000, out_dir=None, folds=5, alpha_sweep=()
):
    """
    Evaluate a stored run and write ``report.md`` / ``report.json`` / reliability files.

    :return: Path of ``report.md``.
    :rtype: Path
    """
    run = conn.execute(
        "SELECT * FROM pivot.model_run WHERE id = %s", (run_id,)
    ).fetchone()
    params = run["params"]
    level, alpha = params["level"], params["alpha"]
    taxonomy = Taxonomy.load(conn, run["attack_version"])
    fidelities = (
        None if params["fidelities"] == "level default" else tuple(params["fidelities"])
    )
    level_inc = {}
    for lv in levels_for(level):
        p = Params(lv, tuple(params["allowed_bases"]), fidelities, params["self_loops"])
        level_inc[lv] = {
            i.id: i
            for i in counting.load_incidents(conn, p, taxonomy, run["corpus_filter"])
        }
    incidents = level_inc[level]
    ids = sorted(incidents)
    if len(ids) < 2:
        raise RuntimeError("need at least two incidents to evaluate")
    rng = np.random.default_rng(seed)

    results = {}
    split, note = _time_split(incidents)
    if split:
        train, test, cutoff = split
        acc = Accumulator(len(test))
        run_split(acc, 0, [train], level_inc, level, taxonomy, alpha, [test])
        results["time_split"] = {
            "cutoff": cutoff,
            "train_incidents": len(train),
            **summarize(acc, rng, n_bootstrap),
        }
    else:
        results["time_split"] = {"note": note}

    k = min(folds, len(ids))
    order = list(rng.permutation(ids))
    parts = [set(order[i::k]) for i in range(k)]
    acc = Accumulator(len(ids))
    run_split(
        acc, 0, [set(ids) - p for p in parts], level_inc, level, taxonomy, alpha, parts
    )
    results[f"cv{k}"] = summarize(acc, rng, n_bootstrap)

    if alpha_sweep:
        results["alpha_sweep"] = {}
        for a in alpha_sweep:
            sweep = Accumulator(len(ids))
            run_split(
                sweep,
                0,
                [set(ids) - p for p in parts],
                level_inc,
                level,
                taxonomy,
                a,
                parts,
            )
            point = summarize(sweep, np.random.default_rng(seed), 1)["methods"]["model"]
            results["alpha_sweep"][str(a)] = {k: v["value"] for k, v in point.items()}

    results["stability"] = stability(level_inc, level, taxonomy, alpha)
    results["vcdb"] = _vcdb_section(conn, taxonomy, level_inc)

    out = (
        Path(out_dir)
        if out_dir
        else Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "eval" / str(run_id)
    )
    out.mkdir(parents=True, exist_ok=True)
    summary = {"run_id": str(run_id), "level": level, "alpha": alpha, "seed": seed, "bootstrap": n_bootstrap,
               "incidents": len(ids), **results}  # fmt: skip
    summary = _clean(summary)
    (out / "report.json").write_text(json.dumps(summary, indent=2, default=str))
    cv = results[f"cv{k}"]
    if cv.get("reliability"):
        (out / "reliability.json").write_text(json.dumps(cv["reliability"], indent=2))
        _plot_reliability(cv["reliability"], out / "reliability.png")
    from attack_pivot.model.report import render

    (out / "report.md").write_text(render(summary, run))
    from psycopg.types.json import Jsonb

    conn.execute(
        "UPDATE pivot.model_run SET eval = %s WHERE id = %s",
        (Jsonb(json.loads(json.dumps(summary, default=str))), run_id),
    )
    conn.commit()
    return out / "report.md"


def _clean(value):
    """JSON-safe copy: NaN/inf become ``None`` (PostgreSQL ``jsonb`` rejects them)."""
    if isinstance(value, float) and not np.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def _vcdb_section(conn, taxonomy, level_inc):
    from attack_pivot.model import vcdb_diag
    from attack_pivot.normalize import attack

    if not conn.execute("SELECT 1 FROM pivot.veris_incident LIMIT 1").fetchone():
        return {"note": "no VCDB records loaded"}
    index = attack.load_index(conn, taxonomy.version)
    mapping = vcdb_diag.load_mapping(
        conn, taxonomy, lambda t: attack.normalize_technique(t, index)[0]
    )
    docs = (
        r["raw"]
        for r in conn.execute("SELECT raw FROM pivot.veris_incident WHERE has_sequence")
    )
    vcdb, used, skipped = vcdb_diag.tactic_counts(docs, mapping, taxonomy)
    tactic_inc = level_inc.get("tactic")
    if (
        tactic_inc is None
    ):  # the run's level chain always stores tactic unless level == tactic only
        return {"note": "tactic level not part of this run"}
    rest = counting.count(list(tactic_inc.values())).n_ab
    return {
        "vcdb_records_used": used,
        "vcdb_records_skipped_unmappable": skipped,
        **vcdb_diag.divergence(vcdb, rest),
    }


def _plot_reliability(bins, path):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(4.5, 4.5))
    xs = [b["mean_p"] for b in bins if b["n"] and b["mean_p"] is not None]
    ys = [b["observed"] for b in bins if b["n"] and b["mean_p"] is not None]
    ax.plot([0, 1], [0, 1], "--", color="grey", label="perfect")
    ax.plot(xs, ys, "o-", label="model")
    ax.set_xlabel("predicted probability (bin mean)")
    ax.set_ylabel("observed frequency")
    ax.set_title("Reliability (all candidate predictions, CV)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
