"""Run collectors and manual imports into ``pivot.report`` (SPEC §6.2)."""

import logging
import mimetypes
from collections import Counter
from pathlib import Path

from attack_pivot.collect import collectors, store
from attack_pivot.collect.http import (
    AccessDenied,
    FetchError,
    PoliteClient,
    RobotsDisallowed,
)
from attack_pivot.collect.text import MIN_TEXT_CHARS, canonical_url, extract_text

logger = logging.getLogger(__name__)


def get_source(conn, name):
    """An enabled (licence-reviewed) source row. Disabled sources are refused: fail closed."""
    row = conn.execute("SELECT * FROM pivot.source WHERE name = %s", (name,)).fetchone()
    if row is None:
        raise RuntimeError(f"no source named {name!r}; run `afp sources load`")
    if not row["enabled"]:
        raise RuntimeError(
            f"source {name!r} is not enabled: review its licence/ToS (docs/pivot/source-review.md) "
            "and run `afp sources enable`"
        )
    return row


def enabled_collectable(conn):
    """Enabled sources that have a network collector (not manual, not the structured repos)."""
    return conn.execute(
        "SELECT * FROM pivot.source WHERE enabled AND collector = ANY(%s) "
        "AND source_class NOT IN ('structured_dataset', 'detection_repo') ORDER BY name",
        (list(collectors.COLLECTORS),),
    ).fetchall()


def make_client(source, **kwargs):
    interval = (source["collector_config"] or {}).get("rate_limit_seconds", 5)
    return PoliteClient(min_interval=float(interval), **kwargs)


def _fetch_item(conn, source, client, item, stats):
    """Fetch, extract and store one discovered item; update ``stats``."""
    try:
        response = client.get(item.url)
        text = extract_text(
            response.content, response.headers.get("content-type"), item.url
        )
    except RobotsDisallowed:
        stats["robots_disallowed"] += 1
        return False
    except AccessDenied:
        stats["access_denied"] += 1
        return False
    except (
        FetchError,
        ValueError,
    ) as e:  # ValueError: PdfExtractionError and decode problems
        logger.warning("%s: %s", item.url, e)
        stats["errors"] += 1
        return False
    if len(text) < MIN_TEXT_CHARS:
        stats["too_short"] += 1
        return False
    report_id, duplicate = store.save_report(
        conn,
        source,
        text=text,
        url=item.url,
        title=item.title,
        published=item.published,
    )
    conn.commit()
    if duplicate:
        stats[f"duplicate_{duplicate}"] += 1
        return False
    stats["new"] += 1
    return True


def collect_source(conn, source, client, since=None, limit=None, items=None):
    """
    Discover and store new reports for one source.

    :param date since: Skip items published before this date (undated items are kept).
    :param int limit: Stop after this many new reports.
    :param list items: Use these items instead of running the source's collector.
    :return: Counts: ``discovered``, ``new``, ``duplicate_url``, ``duplicate_sha256``, ``old``,
        ``too_short``, ``robots_disallowed``, ``access_denied``, ``errors``, ``discovery_failed``.
    :rtype: Counter
    """
    stats = Counter()
    if items is None:
        try:
            items = collectors.COLLECTORS[source["collector"]](client, source)
        except (RobotsDisallowed, AccessDenied, FetchError, ValueError) as e:
            logger.warning("%s: discovery failed: %s", source["name"], e)
            stats["discovery_failed"] += 1
            return stats
    items = sorted(
        items,
        key=lambda i: (
            i.published is None,
            -(i.published.toordinal() if i.published else 0),
        ),
    )
    stats["discovered"] = len(items)
    for item in items:
        if limit is not None and stats["new"] >= limit:
            break
        if since and item.published and item.published < since:
            stats["old"] += 1
        elif store.known(conn, canonical_url(item.url)):
            stats["duplicate_url"] += 1
        else:
            _fetch_item(conn, source, client, item, stats)
    return stats


def read_url_list(path):
    """URLs from a text file, one per line; ``#`` comments and blank lines ignored."""
    urls = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            urls.append(collectors.Item(line))
    return urls


def import_files(conn, source, paths, tlp=None):
    """
    Store files the owner already has (txt/md/html/pdf) as reports of ``source``. The TLP comes from
    the caller (ISAC material takes the TLP stamped on the document, so it is mandatory there).
    """
    if source["source_class"] == "isac" and not tlp:
        raise RuntimeError("ISAC material needs --tlp (TLP is set from the document)")
    stats = Counter()
    for path in map(Path, paths):
        stats["discovered"] += 1
        try:
            text = extract_text(
                path.read_bytes(), mimetypes.guess_type(path.name)[0], path.name
            )
        except (OSError, ValueError) as e:
            logger.warning("%s: %s", path, e)
            stats["errors"] += 1
            continue
        if len(text) < MIN_TEXT_CHARS:
            stats["too_short"] += 1
            continue
        _, duplicate = store.save_report(
            conn, source, text=text, title=path.stem, tlp=tlp
        )
        conn.commit()
        stats[f"duplicate_{duplicate}" if duplicate else "new"] += 1
    return stats
