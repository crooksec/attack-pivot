"""Markdown rendering of an evaluation summary."""

from attack_pivot.model.evaluate import LOWER_IS_BETTER, METHODS, METRICS

LABELS = {
    "model": "Markov model",
    "uniform": "Uniform",
    "popularity": "Popularity",
    "cooccurrence": "Co-occurrence (TIE-style)",
    "tactic_order": "Tactic-order prior",
}
SHOWN = (*METRICS, "ece", "ece_p>=0.05")
GO_NO_GO_NOTE = (
    "PRD §5 thresholds (proposed, unconfirmed): (1) the model beats popularity on hit@5 and MRR with the "
    "bootstrap 95% CI of the difference excluding 0 (time-based split); (2) ECE ≤ 0.10 over bins with p ≥ 0.05; "
    "(3) leave-one-source-class-out Spearman ρ ≥ 0.7 on the top-200 transitions; (4) ≥ 85% edge direction and "
    "order_basis accuracy in the human review sample (not measured here)."
)


def _fmt(x, digits=3):
    return "n/a" if x is None else f"{x:.{digits}f}"


def _metric_table(block):
    lines = ["| Method | " + " | ".join(SHOWN) + " |", "|---|" + "---|" * len(SHOWN)]
    for m in METHODS:
        row = block["methods"][m]
        cells = [
            f"{_fmt(row[k]['value'])} [{_fmt(row[k]['ci'][0])}, {_fmt(row[k]['ci'][1])}]"
            for k in SHOWN
        ]
        lines.append(f"| {LABELS[m]} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _diff_table(block):
    lines = ["| Baseline | " + " | ".join(SHOWN) + " |", "|---|" + "---|" * len(SHOWN)]
    for base, metrics in block["vs_baseline"].items():
        cells = []
        for k in SHOWN:
            d = metrics[k]
            mark = (
                "✓"
                if d["ci_excludes_zero"] and d["model_better"]
                else ("✗" if d["ci_excludes_zero"] else "·")
            )
            cells.append(
                f"{mark} {_fmt(d['diff'])} [{_fmt(d['ci'][0])}, {_fmt(d['ci'][1])}]"
            )
        lines.append(f"| vs {LABELS[base]} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _block(title, block):
    if "note" in block:
        return f"## {title}\n\nNot run — {block['note']}.\n"
    head = f"## {title}\n\n{block['n_incidents']} held-out incidents, {block['n_transitions']} held-out transitions"
    if "cutoff" in block:
        head += f"; train ≤ {block['cutoff']} ({block['train_incidents']} incidents)"
    lower = ", ".join(sorted(LOWER_IS_BETTER))
    return (
        f"{head}.\n\nMetric [95% bootstrap CI over test incidents]. Lower is better for: {lower}. "
        f"hit@k and MRR use expected rank under random tie-breaking.\n\n{_metric_table(block)}\n\n"
        f"### Model minus baseline\n\n✓ = CI excludes 0 and the model is better, ✗ = CI excludes 0 and the model "
        f"is worse, · = CI includes 0.\n\n{_diff_table(block)}\n"
    )


def render(summary, run):
    """The evaluation report as markdown."""
    stats = run["corpus_stats"]
    out = [
        f"# Evaluation — run {summary['run_id']}",
        "",
        f"Level **{summary['level']}**, α = {summary['alpha']}, ATT&CK {run['attack_version']}, seed {summary['seed']}, "
        f"{summary['bootstrap']} bootstrap resamples. Corpus: {stats['incidents']} incidents, "
        f"{stats['incident_level_transitions']:g} incident-level ordered transitions, "
        f"{stats['unique_transition_pairs']} unique pairs; by source class {stats['by_source_class']}; "
        f"incidents without a date: {stats['incidents_without_date']}.",
        "",
        "> Small corpora give wide intervals: read the CIs, not the point values.",
        "",
        _block(
            "Time-based split (train ≤ 80th-percentile date, test after)",
            summary["time_split"],
        ),
    ]
    cv_key = next(k for k in summary if k.startswith("cv"))
    out.append(
        _block(f"Incident-grouped {cv_key[2:]}-fold cross-validation", summary[cv_key])
    )
    if summary.get("alpha_sweep"):
        out += [
            "## α sweep (cross-validation, model only)",
            "",
            "Prior strength α trades trust in sparse counts against the backoff prior. Point values, no CIs.",
            "",
            "| α | " + " | ".join(SHOWN) + " |",
            "|---|" + "---|" * len(SHOWN),
        ]
        for a, row in summary["alpha_sweep"].items():
            out.append(f"| {a} | " + " | ".join(_fmt(row[k]) for k in SHOWN) + " |")
        out.append("")
    out += ["## Calibration", ""]
    cv = summary[cv_key]
    if cv.get("reliability"):
        out += [
            "Reliability over every (held-out transition, candidate) prediction, pooled across folds; "
            "`reliability.png` / `reliability.json` hold the same data.",
            "",
            "| bin | n | mean p | observed |",
            "|---|---|---|---|",
        ]
        for b in cv["reliability"]:
            out.append(
                f"| {b['bin'][0]:.1f}–{b['bin'][1]:.1f} | {b['n']:.0f} | {_fmt(b['mean_p'], 4)} | {_fmt(b['observed'], 4)} |"
            )
    out += [
        "",
        "## Stability (leave-one-source-class-out)",
        "",
        "| Left-out class | incidents removed | Spearman ρ (top transitions) |",
        "|---|---|---|",
    ]
    for cls, r in summary["stability"].items():
        out.append(
            f"| {cls} | {r.get('left_out_incidents', '—')} | {_fmt(r['rho'])}{'' if r['rho'] is not None else ' — ' + r.get('note', '')} |"
        )
    v = summary["vcdb"]
    out += ["", "## VCDB vs the narrative corpus (tactic-level bias diagnostic)", ""]
    if "note" in v:
        out.append(v["note"])
    else:
        out += [
            f"VCDB records with an ordered, fully mappable chain: {v['vcdb_records_used']} "
            f"(skipped as unmappable: {v['vcdb_records_skipped_unmappable']}).",
            f"Jensen–Shannon distance (base 2) between joint tactic-transition distributions: **{_fmt(v['joint'])}**; "
            f"row-wise mean: {_fmt(v['rowwise_mean'])}.",
            "",
            "| pair | VCDB share | rest share |",
            "|---|---|---|",
        ]
        out += [
            f"| {g['pair']} | {_fmt(g['vcdb_share'])} | {_fmt(g['rest_share'])} |"
            for g in v["largest_gaps"]
        ]
    out += ["", "## Go / no-go", "", GO_NO_GO_NOTE, ""]
    return "\n".join(out) + "\n"
