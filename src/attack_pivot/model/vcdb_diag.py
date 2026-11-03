"""VCDB-vs-rest bias diagnostic at tactic level (PRD R1/R11, SPEC §6.6).

VCDB is coded from public disclosures, not vendor telemetry, so how its tactic transitions differ
from the narrative-report corpus is a measure of selection bias. VCDB transitions are *not* part of
any model: this builds a tactic-level count table from ordered ``plus.event_chain`` records only
for this comparison. A chain step names only a VERIS action category, so a step's tactics are
pooled from the mapped techniques of that category's varieties/vectors in the same record (each
VERIS path spreads weight 1/k over its k techniques; each technique spreads 1/k over its tactics).
Records with a step that has no mapped path are skipped.
"""

from collections import defaultdict

import numpy as np
from scipy.spatial.distance import jensenshannon

from attack_pivot.ingest.vcdb import CHAIN_CATEGORY, event_chain, veris_paths
from attack_pivot.model.taxonomy import END, START


def load_mapping(conn, taxonomy, normalize):
    """
    ``veris_attack_map`` as ``{veris_path: [technique ids valid in the pinned version]}``.

    :param normalize: Callable mapping a declared technique ID to the pinned version (or ``None``).
    """
    mapping = defaultdict(set)
    for r in conn.execute(
        "SELECT veris_path, technique_id FROM pivot.veris_attack_map"
    ):
        technique = normalize(r["technique_id"])
        if technique and technique in taxonomy.tactics:
            mapping[r["veris_path"]].add(technique)
    return {p: sorted(t) for p, t in mapping.items()}


def _step_tactics(doc, category, mapping, taxonomy):
    paths = [
        p
        for p in veris_paths(doc)
        if p.startswith(f"action.{category}.") and p in mapping
    ]
    weights = defaultdict(float)
    for p in paths:
        for technique in mapping[p]:
            weights[technique] += 1.0 / len(mapping[p])
    tactics = defaultdict(float)
    for technique, w in weights.items():
        names = taxonomy.tactics.get(technique) or []
        for t in names:
            tactics[t] += w / len(names)
    total = sum(tactics.values())
    return {t: w / total for t, w in tactics.items()} if total else {}


def tactic_counts(docs, mapping, taxonomy):
    """
    Tactic-level transition counts from ordered VCDB records.

    :param docs: Iterable of VCDB documents (with ``plus.event_chain``).
    :return: ``(counts {(a, b): weight}, used, skipped)``
    """
    counts, used, skipped = defaultdict(float), 0, 0
    for doc in docs:
        chain = event_chain(doc)
        if len(chain) < 2:
            continue
        steps = [
            (
                _step_tactics(doc, CHAIN_CATEGORY[s.get("action")], mapping, taxonomy)
                if s.get("action") in CHAIN_CATEGORY
                else {}
            )
            for s in chain
        ]
        if not all(steps):
            skipped += 1
            continue
        used += 1
        pairs = defaultdict(float)
        for ta, wa in steps[0].items():
            pairs[(START, ta)] += wa
        for left, right in zip(steps, steps[1:]):
            for ta, wa in left.items():
                for tb, wb in right.items():
                    pairs[(ta, tb)] += wa * wb
        for ta, wa in steps[-1].items():
            pairs[(ta, END)] += wa
        for pair, w in pairs.items():
            counts[pair] += min(1.0, w)
    return dict(counts), used, skipped


def divergence(vcdb, rest):
    """
    Jensen–Shannon distance (base 2, 0 = identical, 1 = disjoint) between two tactic-transition
    count tables: over the joint distribution of pairs, and the mean over source tactics of the
    row-wise distance of add-one smoothed conditionals, weighted by the VCDB row mass.

    :return: dict with ``joint``, ``rowwise_mean``, ``pairs`` and per-pair largest gaps.
    """
    keys = sorted(set(vcdb) | set(rest))
    if not vcdb or not rest:
        return {
            "joint": None,
            "rowwise_mean": None,
            "pairs": len(keys),
            "largest_gaps": [],
        }
    v = np.array([vcdb.get(k, 0.0) for k in keys])
    r = np.array([rest.get(k, 0.0) for k in keys])
    joint = float(jensenshannon(v / v.sum(), r / r.sum(), base=2))
    dests = sorted({b for _, b in keys})
    rows, mass = [], []
    for a in sorted({a for a, _ in keys}):
        rv = np.array([vcdb.get((a, b), 0.0) for b in dests]) + 1
        rr = np.array([rest.get((a, b), 0.0) for b in dests]) + 1
        rows.append(float(jensenshannon(rv / rv.sum(), rr / rr.sum(), base=2)))
        mass.append(sum(vcdb.get((a, b), 0.0) for b in dests))
    rowwise = float(np.average(rows, weights=mass)) if sum(mass) else None
    gaps = sorted(
        keys,
        key=lambda k: -abs(v[keys.index(k)] / v.sum() - r[keys.index(k)] / r.sum()),
    )[:5]
    return {
        "joint": joint,
        "rowwise_mean": rowwise,
        "pairs": len(keys),
        "largest_gaps": [
            {
                "pair": f"{a}>{b}",
                "vcdb_share": float(vcdb.get((a, b), 0) / v.sum()),
                "rest_share": float(rest.get((a, b), 0) / r.sum()),
            }
            for a, b in gaps
        ],
    }
