"""Triage precision check against a labelled sample (TASKS P2.3: precision >= 0.8 on 100 reports)."""

import csv
import random
from pathlib import Path

TARGET_PRECISION = 0.8
SAMPLE_FIELDS = [
    "report_id",
    "source",
    "source_class",
    "title",
    "url",
    "text_path",
    "label",
]
YES, NO = {"yes", "y", "1", "true"}, {"no", "n", "0", "false"}


def sample(conn, n=100, seed=0):
    """
    A stratified (by source class), seeded sample of triaged reports for hand labelling. The
    system's decision is deliberately left out so it cannot anchor the labeller.
    """
    rows = conn.execute(
        "SELECT r.id, s.name AS source, s.source_class, r.title, r.url, r.text_path "
        "FROM pivot.report r JOIN pivot.source s ON s.id = r.source_id "
        "WHERE r.triage_status IN ('candidate', 'rejected', 'extracted') AND r.text_path IS NOT NULL "
        "AND r.triage IS NOT NULL ORDER BY r.id"
    ).fetchall()
    by_class = {}
    for r in rows:
        by_class.setdefault(r["source_class"], []).append(r)
    rng = random.Random(seed)
    chosen = []
    pools = {k: rng.sample(v, len(v)) for k, v in sorted(by_class.items())}
    while len(chosen) < n and any(pools.values()):  # round-robin across classes
        for pool in pools.values():
            if pool and len(chosen) < n:
                chosen.append(pool.pop())
    return chosen


def write_sample(rows, path):
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, SAMPLE_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "report_id": r["id"],
                    "source": r["source"],
                    "source_class": r["source_class"],
                    "title": r["title"],
                    "url": r["url"],
                    "text_path": r["text_path"],
                    "label": "",
                }
            )


def read_labels(path):
    """``{report_id: bool}`` for rows with a yes/no ``label`` (blank rows are skipped)."""
    labels = {}
    with Path(path).open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            value = (row.get("label") or "").strip().lower()
            if value in YES:
                labels[row["report_id"]] = True
            elif value in NO:
                labels[row["report_id"]] = False
            elif value:
                raise RuntimeError(
                    f"report {row['report_id']}: label {value!r} is not yes/no"
                )
    return labels


def evaluate(conn, labels):
    """
    Precision and recall of the ``candidate`` decision against labels meaning "is an intrusion
    narrative with at least three techniques".

    :return: Counts, precision, recall and ``passes`` (precision >= 0.8), plus per-source-class
        precision.
    :rtype: dict
    """
    decided = {
        str(r["id"]): (r["triage_status"], r["source_class"])
        for r in conn.execute(
            "SELECT r.id, r.triage_status, s.source_class FROM pivot.report r "
            "JOIN pivot.source s ON s.id = r.source_id WHERE r.id::text = ANY(%s)",
            (list(labels),),
        )
    }
    tp = fp = fn = tn = 0
    per_class = {}
    for rid, truth in labels.items():
        if rid not in decided:
            raise RuntimeError(f"report {rid} is not in the database")
        status, cls = decided[rid]
        predicted = status in ("candidate", "extracted")
        tp += predicted and truth
        fp += predicted and not truth
        fn += (not predicted) and truth
        tn += (not predicted) and not truth
        c = per_class.setdefault(cls, [0, 0])
        if predicted:
            c[0] += truth
            c[1] += 1
    precision = tp / (tp + fp) if tp + fp else None
    return {
        "n": len(labels),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": tp / (tp + fn) if tp + fn else None,
        "target": TARGET_PRECISION,
        "passes": precision is not None and precision >= TARGET_PRECISION,
        "precision_by_source_class": {k: v[0] / v[1] for k, v in sorted(per_class.items()) if v[1]},
    }  # fmt: skip
