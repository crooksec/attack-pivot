"""Triage reports: heuristics first, then an LLM classification (SPEC §6.3)."""

import logging
from collections import Counter
from pathlib import Path

from psycopg.types.json import Jsonb

from attack_pivot import llm as llm_module
from attack_pivot.triage import classify, heuristics

logger = logging.getLogger(__name__)


def decide(stats, answer):
    """
    Candidate = intrusion narrative AND at least 3 techniques (SPEC §6.3). Without an LLM answer
    (``--heuristics-only``) only cited technique IDs can count, and the record says so.

    :param dict stats: :func:`heuristics.analyze`.
    :param dict answer: :func:`classify.parse_answer`, or ``None`` for heuristics-only.
    :return: ``(status, reason)``
    """
    if answer is None:
        if stats["technique_mentions"] >= heuristics.MIN_TECHNIQUES:
            return (
                "candidate",
                f"heuristic_only:cites_{stats['technique_mentions']}_techniques",
            )
        return "rejected", "heuristic_only:fewer_than_3_cited_techniques"
    if not answer["is_intrusion_narrative"]:
        return "rejected", "llm:not_intrusion_narrative"
    techniques = max(stats["technique_mentions"], answer["technique_count_estimate"])
    if techniques < heuristics.MIN_TECHNIQUES:
        return "rejected", f"llm:fewer_than_3_techniques({techniques})"
    return "candidate", f"llm:intrusion_narrative;techniques={techniques}"


def _pending(conn, limit, retriage):
    """Stored reports to triage: ``new`` ones, or every non-extracted one when re-triaging."""
    states = "('new', 'candidate', 'rejected')" if retriage else "('new')"
    return conn.execute(
        "SELECT id, text_path FROM pivot.report WHERE text_path IS NOT NULL "
        f"AND triage_status IN {states} ORDER BY created_at"
        + (" LIMIT %s" if limit else ""),
        (limit,) if limit else (),
    ).fetchall()


def triage_reports(conn, index, client=None, limit=None, retriage=False):
    """
    Triage stored reports.

    :param attack.TechniqueIndex index: Pinned ATT&CK version, for counting cited IDs.
    :param client: An :class:`~attack_pivot.llm.LlmClient`; ``None`` runs heuristics only.
    :param bool retriage: Also redo reports already decided (not ones already extracted).
    :return: Counter of ``candidate``, ``rejected``, ``llm_calls``, ``llm_failed``, ``skipped``.
    :rtype: Counter
    """
    counts = Counter()
    for row in _pending(conn, limit, retriage):
        try:
            text = Path(row["text_path"]).read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("report %s: %s", row["id"], e)
            counts["skipped"] += 1
            continue
        stats = heuristics.analyze(text, index)
        passes, why = heuristics.first_pass(stats)
        answer, record = None, {"mode": "heuristics_only", **stats}
        if not passes:
            decision = ("rejected", why)
            record["mode"] = "heuristics"
        elif client is not None:
            record["mode"] = "llm"
            try:
                answer, usage = classify.classify(client, text)
                llm_module.log_call(
                    conn,
                    "triage",
                    client,
                    usage,
                    report_id=row["id"],
                    ok=answer is not None,
                )
                counts["llm_calls"] += 1
            except (
                Exception
            ) as e:  # provider errors vary; leave the report 'new' and retry later
                logger.warning("report %s: LLM call failed: %s", row["id"], e)
                llm_module.log_call(
                    conn, "triage", client, {}, report_id=row["id"], ok=False
                )
                conn.commit()
                counts["llm_failed"] += 1
                continue
            if answer is None:
                counts["llm_failed"] += 1
                conn.commit()
                continue
            record.update(llm=answer, model=client.model, provider=client.provider_id)
            decision = decide(stats, answer)
        else:
            decision = decide(stats, None)
        status, reason = decision
        conn.execute(
            "UPDATE pivot.report SET triage_status = %s, triage_reason = %s, technique_mentions = %s, "
            "triage = %s WHERE id = %s",
            (status, reason, stats["technique_mentions"], Jsonb(record), row["id"]),
        )
        conn.commit()
        counts[status] += 1
    return counts
