"""
Search discovery: ask Serper/Brave for report URLs, queue them, and fetch only what a
licence-reviewed source covers.

A search result is a pointer, not permission. Fetching goes through
:func:`attack_pivot.collect.run.collect_source`, so robots.txt, rate limits and the enabled-source
check apply exactly as for any other collection.
"""

import logging
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from attack_pivot.collect import collectors, run
from attack_pivot.collect.text import canonical_url
from attack_pivot.search import providers
from attack_pivot.settings import options, redact, secrets

logger = logging.getLogger(__name__)


def current_month():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def selected_providers(conn):
    """The providers the ``search.provider`` option selects, in call order."""
    choice = options.get(conn, "search.provider")
    return {"off": [], "serper": ["serper"], "brave": ["brave"]}.get(
        choice, ["serper", "brave"]
    )


def used(conn, provider):
    row = conn.execute(
        "SELECT queries FROM pivot.search_usage WHERE provider = %s AND month = %s",
        (provider, current_month()),
    ).fetchone()
    return row["queries"] if row else 0


def plan(conn):
    """What a search would do now: per selected provider, key present, used and budget."""
    out = []
    for name in selected_providers(conn):
        key_name = providers.PROVIDERS[name][0]
        out.append(
            {
                "provider": name,
                "has_key": secrets.resolve(conn, key_name) is not None,
                "used": used(conn, name),
                "budget": options.get(conn, f"search.budget.{name}"),
            }
        )
    return out


def _count_query(conn, provider):
    """Record the query before it is sent: a budget is a cap, so over-counting is the safe side."""
    conn.execute(
        "INSERT INTO pivot.search_usage (provider, month, queries) VALUES (%s, %s, 1) "
        "ON CONFLICT (provider, month) DO UPDATE SET queries = search_usage.queries + 1",
        (provider, current_month()),
    )
    conn.commit()


def search(conn, query, http=None):
    """
    Run ``query`` against the selected providers and queue the results.

    :param httpx.Client http: For tests; defaults to a new client.
    :return: Counts: ``queries``, ``results``, ``queued``, ``already_queued``, ``known_report``,
        ``no_key``, ``over_budget``, ``failed``.
    :rtype: Counter
    """
    stats = Counter()
    chosen = selected_providers(conn)
    if not chosen:
        raise RuntimeError(
            "search is off: set search.provider (afp settings set search.provider serper)"
        )
    redact.register(secrets.all_values(conn))
    num = options.get(conn, "search.results_per_query")
    freshness = options.get(conn, "search.freshness")
    own_client = http is None
    http = http or httpx.Client()
    try:
        seen = set()
        for name in chosen:
            key_name, call = providers.PROVIDERS[name]
            api_key = secrets.resolve(conn, key_name)
            if api_key is None:
                stats["no_key"] += 1
                continue
            if used(conn, name) >= options.get(conn, f"search.budget.{name}"):
                stats["over_budget"] += 1
                continue
            _count_query(conn, name)
            stats["queries"] += 1
            try:
                hits = call(http, api_key, query, num, freshness)
            except providers.SearchError as e:
                logger.warning("%s", redact.redact(e, [api_key]))
                stats["failed"] += 1
                continue
            for hit in hits:
                stats["results"] += 1
                _queue(conn, hit, query, seen, stats)
    finally:
        if own_client:
            http.close()
    conn.commit()
    return stats


def _queue(conn, hit, query, seen, stats):
    parts = urlsplit(hit.url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return
    canonical = canonical_url(hit.url)
    if canonical in seen:
        return
    seen.add(canonical)
    if conn.execute(
        "SELECT 1 FROM pivot.report WHERE url = %s", (canonical,)
    ).fetchone():
        stats["known_report"] += 1
        return
    inserted = conn.execute(
        "INSERT INTO pivot.discovered_url "
        "(url, canonical_url, domain, title, snippet, provider, query, rank) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (canonical_url) DO NOTHING",
        (
            hit.url.strip(),
            canonical,
            parts.hostname.lower(),
            hit.title,
            hit.snippet,
            hit.provider,
            query,
            hit.rank,
        ),
    ).rowcount
    stats["queued" if inserted else "already_queued"] += 1


# -- review queue -----------------------------------------------------------------------------


def queue(conn, status="queued", limit=100):
    """Discovered URLs with the source (if any) their domain maps to."""
    rows = conn.execute(
        "SELECT * FROM pivot.discovered_url WHERE status = %s "
        "ORDER BY found_at DESC, rank LIMIT %s",
        (status, limit),
    ).fetchall()
    for row in rows:
        source = domain_source(conn, row["domain"])
        row["source"] = source["name"] if source else None
        row["source_enabled"] = bool(source and source["enabled"])
    return rows


def domain_source(conn, host):
    """The source whose mapped domain is ``host`` or a parent of it (longest match), else ``None``."""
    host = host.lower()
    return conn.execute(
        "SELECT s.* FROM pivot.source_domain d JOIN pivot.source s ON s.id = d.source_id "
        "WHERE %s = d.domain OR right(%s, length(d.domain) + 1) = '.' || d.domain "
        "ORDER BY length(d.domain) DESC LIMIT 1",
        (host, host),
    ).fetchone()


def map_domain(conn, domain, source_name):
    """Declare that ``domain`` is covered by ``source_name``'s licence review."""
    domain = domain.strip().lower().removeprefix("www.")
    if not domain or "/" in domain or " " in domain:
        raise ValueError("domain must be a bare host name such as example.com")
    source = conn.execute(
        "SELECT id FROM pivot.source WHERE name = %s", (source_name,)
    ).fetchone()
    if source is None:
        raise RuntimeError(f"no source named {source_name!r}")
    conn.execute(
        "INSERT INTO pivot.source_domain (domain, source_id) VALUES (%s, %s) "
        "ON CONFLICT (domain) DO UPDATE SET source_id = EXCLUDED.source_id",
        (domain, source["id"]),
    )
    conn.commit()
    return domain


def unmap_domain(conn, domain):
    removed = conn.execute(
        "DELETE FROM pivot.source_domain WHERE domain = %s", (domain.strip().lower(),)
    ).rowcount
    conn.commit()
    return bool(removed)


def reject(conn, ident):
    """Reject a queued URL by id or URL; returns whether one was queued."""
    row = conn.execute(
        "UPDATE pivot.discovered_url SET status = 'rejected', decided_at = now() "
        "WHERE status = 'queued' AND (id::text = %s OR canonical_url = %s)",
        (ident, canonical_url(ident) if "://" in ident else ident),
    ).rowcount
    conn.commit()
    return bool(row)


def fetch_queued(conn, client, limit=None):
    """
    Fetch queued URLs whose domain maps to an enabled source. Others stay queued.

    :return: Counts: ``fetched``, ``duplicate``, ``failed``, ``unmapped``, ``source_disabled``.
    :rtype: Counter
    """
    stats = Counter()
    rows = conn.execute(
        "SELECT * FROM pivot.discovered_url WHERE status = 'queued' ORDER BY found_at, rank"
    ).fetchall()
    for row in rows:
        if limit is not None and stats["fetched"] + stats["duplicate"] >= limit:
            break
        source = domain_source(conn, row["domain"])
        if source is None:
            stats["unmapped"] += 1
            continue
        if not source["enabled"]:
            stats["source_disabled"] += 1
            continue
        result = run.collect_source(
            conn,
            source,
            client,
            items=[collectors.Item(row["url"], row["title"])],
        )
        _record_outcome(conn, row, result, stats)
    return stats


def _record_outcome(conn, row, result, stats):
    if result["new"]:
        status, note = "fetched", None
        stats["fetched"] += 1
    elif result["duplicate_url"] or result["duplicate_sha256"]:
        status, note = "fetched", "already stored"
        stats["duplicate"] += 1
    else:
        reasons = [
            k
            for k in (
                "robots_disallowed",
                "access_denied",
                "too_short",
                "errors",
                "old",
            )
            if result[k]
        ]
        status, note = "failed", ", ".join(reasons) or "not stored"
        stats["failed"] += 1
    report = conn.execute(
        "SELECT id FROM pivot.report WHERE url = %s", (row["canonical_url"],)
    ).fetchone()
    conn.execute(
        "UPDATE pivot.discovered_url SET status = %s, note = %s, report_id = %s, "
        "decided_at = now() WHERE id = %s",
        (status, note, report["id"] if report else None, row["id"]),
    )
    conn.commit()
