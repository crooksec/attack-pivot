"""Store collected report text locally and register it in ``pivot.report`` (SPEC §6.2)."""

import os
from pathlib import Path

from attack_pivot.collect.text import canonical_url, sha256_text


def reports_dir():
    return Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "reports"


def known(conn, url=None, sha256=None):
    """The reason a report is already stored (``"url"`` or ``"sha256"``), else ``None``."""
    if (
        url
        and conn.execute("SELECT 1 FROM pivot.report WHERE url = %s", (url,)).fetchone()
    ):
        return "url"
    if (
        sha256
        and conn.execute(
            "SELECT 1 FROM pivot.report WHERE sha256 = %s", (sha256,)
        ).fetchone()
    ):
        return "sha256"
    return None


def save_report(conn, source, *, text, url=None, title=None, published=None, tlp=None):
    """
    Write ``text`` to ``DATA_DIR/pivot/reports/<sha256>.txt`` and insert a ``new`` report.

    :param dict source: A ``pivot.source`` row (``id``, ``default_tlp``).
    :return: ``(report_id, None)`` if stored, ``(None, "url"|"sha256")`` if it was a duplicate.
    """
    url = canonical_url(url) if url else None
    digest = sha256_text(text)
    reason = known(conn, url, digest)
    if reason:
        return None, reason
    directory = reports_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.txt"
    path.write_text(text, encoding="utf-8")
    report_id = conn.execute(
        "INSERT INTO pivot.report (source_id, url, title, published_at, retrieved_at, sha256, tlp, "
        "text_path, triage_status) VALUES (%s, %s, %s, %s, now(), %s, %s, %s, 'new') RETURNING id",
        (
            source["id"],
            url,
            title,
            published,
            digest,
            tlp or source["default_tlp"],
            str(path),
        ),
    ).fetchone()["id"]
    return report_id, None
