"""Dirichlet smoothing with hierarchical backoff and credible intervals (SPEC §7.3).

For a source state ``a`` and destination ``b`` at one level::

    p(b|a) = (n_ab + α·q(b|a)) / (n_a + α)

``q`` is the backoff prior built from the parent level's smoothed model::

    sub-technique:  q(b|a) = p_technique(parent(b) | parent(a)) · share(b | parent(b))
    technique:      q(b|a) = Σ_ta w(ta|a) · Σ_{tb∈T(b)} p_tactic(tb | ta) · share(b | tb)
    tactic:         q(b|a) = popularity of b among destinations

``share(b | g)`` is b's add-one share of the destination counts among the members of group g
(its siblings, or the techniques of a tactic), so unseen members still get prior mass. ``w`` is
the 1/k split of a multi-tactic technique. The tactic-level popularity is add-one smoothed over
the vocabulary; with no data at all it is uniform. Everything is dense numpy: the largest level
is about 700 × 700.

The marginal of the Dirichlet posterior is ``Beta(n_ab + α·q, n_a − n_ab + α·(1 − q))``; the
reported interval is its 5th–95th percentile.
"""

from dataclasses import dataclass

import numpy as np
from scipy.stats import beta

from attack_pivot.model.counting import Counts
from attack_pivot.model.taxonomy import END, START

LEVEL_PARENT = {"subtechnique": "technique", "technique": "tactic", "tactic": None}
CI_LOW, CI_HIGH = 0.05, 0.95
_EPS = 1e-12


@dataclass
class LevelModel:
    """Smoothed transition matrices of one level. Rows are sources, columns destinations."""

    level: str
    alpha: float
    sources: list  # START + vocabulary
    dests: list  # vocabulary + END
    n_ab: np.ndarray
    n_a: np.ndarray
    q: np.ndarray
    p: np.ndarray

    def __post_init__(self):
        self.src_index = {s: i for i, s in enumerate(self.sources)}
        self.dst_index = {s: i for i, s in enumerate(self.dests)}

    def interval(self, rows=None, cols=None):
        """5th and 95th percentile of the Beta marginal, as arrays shaped like ``p``."""
        n_ab, n_a, q = self.n_ab, self.n_a[:, None], np.clip(self.q, _EPS, 1 - _EPS)
        a = n_ab + self.alpha * q
        b = np.maximum(n_a - n_ab, 0) + self.alpha * (1 - q)
        return beta.ppf(CI_LOW, a, b), beta.ppf(CI_HIGH, a, b)


def _matrix(counts, sources, dests):
    s_idx = {s: i for i, s in enumerate(sources)}
    d_idx = {s: i for i, s in enumerate(dests)}
    n_ab = np.zeros((len(sources), len(dests)))
    for (a, b), w in counts.n_ab.items():
        if a in s_idx and b in d_idx:
            n_ab[s_idx[a], d_idx[b]] += w
    return n_ab


def _share(marginal, groups):
    """
    Add-one share of each destination within each group.

    :param np.ndarray marginal: Destination counts, one per column.
    :param list[list[int]] groups: Column indices of each group's members.
    :return: ``share[g][col]`` as a dense (groups × columns) matrix, 0 outside the group.
    """
    out = np.zeros((len(groups), len(marginal)))
    for g, members in enumerate(groups):
        total = marginal[members].sum() + len(members)
        out[g, members] = (marginal[members] + 1.0) / total
    return out


def fit_level(level, counts, taxonomy, alpha, parent=None):
    """
    Smooth one level. ``parent`` is the already fitted parent :class:`LevelModel` (required for
    sub-technique and technique levels).

    :param Counts counts: This level's counts.
    :rtype: LevelModel
    """
    vocab = taxonomy.vocabulary(level)
    sources, dests = [START, *vocab], [*vocab, END]
    n_ab = _matrix(counts, sources, dests)
    n_a = n_ab.sum(axis=1)
    marginal = n_ab.sum(axis=0)

    if level == "tactic":
        popularity = (marginal + 1.0) / (marginal.sum() + len(dests))
        q = np.tile(popularity, (len(sources), 1))
    elif level == "technique":
        q = _technique_prior(taxonomy, sources, dests, marginal, parent)
    else:
        q = _subtechnique_prior(taxonomy, sources, dests, marginal, parent)

    p = (n_ab + alpha * q) / (n_a[:, None] + alpha)
    return LevelModel(level, alpha, sources, dests, n_ab, n_a, q, p)


def _technique_prior(taxonomy, sources, dests, marginal, tactic_model):
    t_src, t_dst = tactic_model.src_index, tactic_model.dst_index
    d_idx = {d: i for i, d in enumerate(dests)}
    # share[(tactic)] over the destination columns holding techniques of that tactic
    tactics = [t for t in tactic_model.sources if t != START]
    members = {
        t: [d_idx[x] for x in dests[:-1] if t in taxonomy.tactics.get(x, [])]
        for t in tactics
    }
    share = {t: _share(marginal, [m])[0] if m else None for t, m in members.items()}
    q = np.zeros((len(sources), len(dests)))
    # tactic-level destination mass reaching each technique column, per source tactic
    to_dest = np.zeros((len(tactic_model.sources), len(dests)))
    for ta in tactic_model.sources:
        row = tactic_model.p[t_src[ta]]
        for tb in tactics:
            if share[tb] is not None:
                to_dest[t_src[ta]] += row[t_dst[tb]] * share[tb]
        to_dest[t_src[ta], d_idx[END]] = row[t_dst[END]]
    for i, a in enumerate(sources):
        tactic_of_a = (
            [(START, 1.0)] if a == START else _split(taxonomy.tactics.get(a, []))
        )
        if (
            not tactic_of_a
        ):  # technique in no tactic: fall back to the all-source average
            q[i] = to_dest.mean(axis=0)
            continue
        for ta, w in tactic_of_a:
            q[i] += w * to_dest[t_src[ta]]
    return _renormalise(q)


def _subtechnique_prior(taxonomy, sources, dests, marginal, technique_model):
    m_src, m_dst = technique_model.src_index, technique_model.dst_index
    d_idx = {d: i for i, d in enumerate(dests)}
    groups = {}
    for d in dests[:-1]:
        groups.setdefault(taxonomy.technique_parent(d), []).append(d_idx[d])
    shares = {g: _share(marginal, [m])[0] for g, m in groups.items()}
    q = np.zeros((len(sources), len(dests)))
    for i, a in enumerate(sources):
        pa = a if a == START else taxonomy.technique_parent(a)
        row = technique_model.p[m_src[pa]] if pa in m_src else None
        if row is None:
            q[i] = 1.0 / len(dests)
            continue
        for g, share in shares.items():
            if g in m_dst:
                q[i] += row[m_dst[g]] * share
        q[i, d_idx[END]] = row[m_dst[END]]
    return _renormalise(q)


def _split(tactics):
    return [(t, 1.0 / len(tactics)) for t in tactics]


def _renormalise(q):
    """Rows that lost mass to destinations outside the parent vocabulary sum to 1 again."""
    sums = q.sum(axis=1, keepdims=True)
    return np.where(sums > 0, q / np.where(sums > 0, sums, 1), 1.0 / q.shape[1])


def fit(counts_by_level, taxonomy, alpha=1.0, level="technique"):
    """
    Fit ``level`` and its ancestors.

    :param dict counts_by_level: ``{level: Counts}`` for ``level`` and every ancestor level.
    :return: ``{level: LevelModel}`` including the ancestors.
    :rtype: dict
    """
    chain = []
    cur = level
    while cur:
        chain.append(cur)
        cur = LEVEL_PARENT[cur]
    models = {}
    for lv in reversed(chain):
        parent = models.get(LEVEL_PARENT[lv])
        models[lv] = fit_level(lv, counts_by_level[lv], taxonomy, alpha, parent)
    return models


def estimates(model, top_prior=20):
    """
    Rows for ``transition_estimate``: every observed ``(a, b)`` plus the ``top_prior`` highest
    prior-only successors of each observed ``a`` (``n_ab == 0``: shown as "prior" in the UI).

    :return: dicts with level, src, dst, n_ab, n_a, p_mle, p, ci_low, ci_high.
    :rtype: list[dict]
    """
    low, high = model.interval()
    rows = []
    for i, a in enumerate(model.sources):
        if model.n_a[i] <= 0:
            continue
        observed = np.flatnonzero(model.n_ab[i] > 0)
        prior = np.flatnonzero(model.n_ab[i] == 0)
        prior = prior[np.argsort(-model.p[i, prior], kind="stable")[:top_prior]]
        for j in [*observed, *prior]:
            rows.append(
                {
                    "level": model.level,
                    "src": a,
                    "dst": model.dests[j],
                    "n_ab": float(model.n_ab[i, j]),
                    "n_a": float(model.n_a[i]),
                    "p_mle": float(model.n_ab[i, j] / model.n_a[i]),
                    "p": float(model.p[i, j]),
                    "ci_low": float(low[i, j]),
                    "ci_high": float(high[i, j]),
                }
            )
    return rows
