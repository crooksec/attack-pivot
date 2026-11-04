"""Submit candidate reports to the API, import the resulting ``.afb`` files (SPEC §6.4)."""

import json
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

from attack_pivot.extract import api
from attack_pivot.ingest import load
from attack_pivot.ingest.afb import parse_afb
from attack_pivot.normalize import attack

logger = logging.getLogger(__name__)


def pending(conn, limit=None):
    """
    Candidate reports, most useful first: those whose triage found sequence language, then newest.
    """
    return conn.execute(
        "SELECT r.id, r.title, r.url, r.text_path, r.tlp, r.published_at, r.source_id, "
        "s.name AS source_name, s.publisher "
        "FROM pivot.report r JOIN pivot.source s ON s.id = r.source_id "
        "WHERE r.triage_status = 'candidate' AND r.text_path IS NOT NULL "
        "ORDER BY coalesce((r.triage->'llm'->>'has_sequence_language')::boolean, "
        "(r.triage->>'sequence_heuristic')::boolean, false) DESC, r.published_at DESC NULLS LAST, r.created_at "
        + ("LIMIT %s" if limit else ""),
        (limit,) if limit else (),
    ).fetchall()


def plan(conn, limit=None):
    """
    What :func:`extract_reports` would submit, without calling the API.

    :return: ``{"reports", "unreadable", "chars"}`` (``chars`` is the report text length, which the
        API turns into model calls at its own chunk size).
    """
    out = {"reports": 0, "unreadable": 0, "chars": 0}
    for report in pending(conn, limit):
        try:
            out["chars"] += len(Path(report["text_path"]).read_text(encoding="utf-8"))
        except OSError:
            out["unreadable"] += 1
            continue
        out["reports"] += 1
    return out


def job_metadata(report):
    """What the API is told about the source: title, URL as an external reference, publisher."""
    meta = {"title": report["title"], "source_name": report["source_name"]}
    if report["url"]:
        meta["external_references"] = [report["url"]]
    if report["publisher"]:
        meta["authors"] = [report["publisher"]]
    return {k: v for k, v in meta.items() if v}


def _fetch(client, report, provider_id, model, timeout):
    """Network half of one extraction (runs in a worker thread; no DB access)."""
    text = Path(report["text_path"]).read_text(encoding="utf-8")
    return client.run_text_job(
        text, job_metadata(report), provider_id, model, timeout=timeout
    )


def _log_job(conn, report_id, job_id, audit, ok, latency_ms=None):
    provider, model = api.provider_from_audit(audit)
    conn.execute(
        "INSERT INTO pivot.llm_call (purpose, report_id, provider, model, latency_ms, job_id, ok) "
        "VALUES ('extract', %s, %s, %s, %s, %s, %s)",
        (report_id, provider, model, latency_ms, job_id, ok),
    )
    return provider, model


def _job_seconds(audit):
    stamps = audit.get("timestamps") or {}
    try:
        from datetime import datetime

        start = datetime.fromisoformat(stamps["created_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(stamps["completed_at"].replace("Z", "+00:00"))
        return int((end - start).total_seconds() * 1000)
    except (KeyError, AttributeError, ValueError):
        return None


def extract_reports(
    conn,
    client,
    version,
    limit=None,
    concurrency=4,
    provider_id=None,
    model=None,
    timeout=900.0,
):
    """
    Extract candidate reports through the API and ingest each resulting flow.

    HTTP work runs in ``concurrency`` threads; all database writes happen here, in the calling
    thread, one transaction per report. A failed job marks its report ``failed`` with the reason
    and never stops the batch.

    :return: Counter of ``extracted``, ``failed``, ``transitions``, ``actions``.
    :rtype: Counter
    """
    index = attack.load_index(conn, version)
    if not index.valid:
        raise RuntimeError(f"ATT&CK {version} has no techniques; run `afp attack sync`")
    reports = pending(conn, limit)
    counts = Counter()
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {
            pool.submit(_fetch, client, r, provider_id, model, timeout): r
            for r in reports
        }
        for future in as_completed(futures):
            report = futures[future]
            try:
                afb_bytes, job_id, audit = future.result()
                raw = load.strip_nul(json.loads(afb_bytes))
                parsed = parse_afb(raw, name=report["title"])
                if not parsed.actions:
                    raise ValueError("the extracted flow has no attack actions")
                provider, used_model = _log_job(
                    conn, report["id"], job_id, audit, True, _job_seconds(audit)
                )
                flow = load.ingest_flow(
                    conn, parsed, raw, "afb", path_name=str(report["id"]), sha256=None, version=version,
                    index=index, source_id=report["source_id"], tlp=report["tlp"], report_id=report["id"],
                    llm={"provider": provider, "model": used_model, "job_id": job_id},
                )  # fmt: skip
                conn.commit()
            except (api.JobFailed, httpx.HTTPError, OSError, ValueError, KeyError) as e:
                conn.rollback()
                reason = f"extract:{getattr(e, 'code', None) or type(e).__name__}: {e}"[
                    :300
                ]
                logger.warning("report %s: %s", report["id"], reason)
                job_id = getattr(e, "job_id", None)
                conn.execute(
                    "UPDATE pivot.report SET triage_status = 'failed', triage_reason = %s WHERE id = %s",
                    (reason, report["id"]),
                )
                conn.execute(
                    "INSERT INTO pivot.llm_call (purpose, report_id, job_id, ok) VALUES ('extract', %s, %s, false)",
                    (report["id"], job_id),
                )
                conn.commit()
                counts["failed"] += 1
                continue
            counts["extracted"] += 1
            counts["actions"] += flow["actions"]
            counts["transitions"] += flow["transitions"]
    return counts
