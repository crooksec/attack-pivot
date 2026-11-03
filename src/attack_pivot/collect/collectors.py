"""
Collectors (SPEC §6.2). Each ``discover`` returns :class:`Item` rows (URL, title, date) for a
source; page text is fetched afterwards by :mod:`attack_pivot.collect.run`. Everything goes through
a :class:`~attack_pivot.collect.http.PoliteClient`.
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import date, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import feedparser

from attack_pivot.collect.http import FetchError


@dataclass(frozen=True)
class Item:
    url: str
    title: str | None = None
    published: date | None = None


# -- helpers ------------------------------------------------------------------------------------


def parse_date(value):
    """A ``date`` from an ISO-ish string, a struct_time or a datetime; ``None`` if unparseable."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if hasattr(value, "tm_year"):
        return date(value.tm_year, value.tm_mon, value.tm_mday)
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(value))
    if match:
        try:
            return date(*map(int, match.groups()))
        except ValueError:
            return None
    return None


class _FeedLinks(HTMLParser):
    """``<link rel="alternate" type="application/rss+xml|atom+xml" href=...>`` autodiscovery."""

    def __init__(self):
        super().__init__()
        self.feeds = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if (
            tag == "link"
            and "alternate" in (a.get("rel") or "").lower().split()
            and (a.get("type") or "").lower()
            in ("application/rss+xml", "application/atom+xml")
            and a.get("href")
        ):
            self.feeds.append(a["href"])


def _dot(data, path):
    for key in filter(None, (path or "").split(".")):
        data = data[int(key)] if isinstance(data, list) else data.get(key)
        if data is None:
            return None
    return data


# -- rss ----------------------------------------------------------------------------------------


def discover_feed(client, page_url):
    """The first RSS/Atom feed advertised by a page."""
    parser = _FeedLinks()
    parser.feed(client.get(page_url).text)
    if not parser.feeds:
        raise FetchError(f"no RSS/Atom feed advertised at {page_url}")
    return urljoin(page_url, parser.feeds[0])


def rss(client, source):
    """Entries of the feed at ``collector_config.feed_url`` (or the one the base page advertises)."""
    config = source["collector_config"] or {}
    feed_url = config.get("feed_url") or discover_feed(client, source["base_url"])
    feed = feedparser.parse(client.get(feed_url).content)
    if feed.bozo and not feed.entries:
        raise FetchError(f"{feed_url} is not a readable feed: {feed.bozo_exception}")
    items = []
    for entry in feed.entries:
        link = entry.get("link")
        if link:
            items.append(
                Item(
                    urljoin(feed_url, link),
                    entry.get("title"),
                    parse_date(
                        entry.get("published_parsed") or entry.get("updated_parsed")
                    ),
                )
            )
    return items


# -- sitemap ------------------------------------------------------------------------------------


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _sitemap_urls(xml_bytes):
    """``(kind, [(loc, lastmod)])`` for a sitemap or sitemap index."""
    root = ET.fromstring(xml_bytes)
    rows = []
    for node in root:
        fields = {_local(c.tag): (c.text or "").strip() for c in node}
        if fields.get("loc"):
            rows.append((fields["loc"], fields.get("lastmod")))
    return ("index" if _local(root.tag) == "sitemapindex" else "urlset"), rows


def sitemap(client, source):
    """
    URLs from the sitemap(s) at ``collector_config.sitemap_url`` (default: the ``Sitemap:`` lines
    of robots.txt, else ``/sitemap.xml``), optionally filtered by ``url_pattern`` (a regex).
    """
    config = source["collector_config"] or {}
    base = source["base_url"]
    queue = (
        [config["sitemap_url"]]
        if config.get("sitemap_url")
        else client.sitemaps(base)
        or [f"{urlsplit(base).scheme}://{urlsplit(base).netloc}/sitemap.xml"]
    )
    pattern = re.compile(config["url_pattern"]) if config.get("url_pattern") else None
    items, seen, fetched = [], set(), 0
    while queue and fetched < config.get("max_sitemaps", 20):
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        fetched += 1
        kind, rows = _sitemap_urls(client.get(url).content)
        for loc, lastmod in rows:
            if kind == "index":
                queue.append(loc)
            elif not pattern or pattern.search(loc):
                items.append(Item(loc, None, parse_date(lastmod)))
    return items


# -- github_repo --------------------------------------------------------------------------------


def github_repo(client, source):
    """
    URL discovery from an index file in a public repository, for bulk collections such as
    APTnotes. ``collector_config``: ``index_file`` (path in the repo), ``branch`` (default
    ``master``), ``format`` (``aptnotes``: a JSON list of ``{Title, Link, Date}``).
    The listed originals are fetched individually, and each is subject to robots.txt.
    """
    config = source["collector_config"] or {}
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)", source["base_url"] or "")
    if not match or not config.get("index_file"):
        raise FetchError(
            f"{source['name']}: github_repo needs a github.com base_url and collector_config.index_file"
        )
    owner, repo = match.groups()
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{config.get('branch', 'master')}/{config['index_file']}"
    records = json.loads(client.get(raw).content)
    if config.get("format", "aptnotes") != "aptnotes":
        raise FetchError(f"unknown index format {config['format']!r}")
    return [
        Item(r["Link"], r.get("Title"), parse_date(r.get("Date")))
        for r in records
        if isinstance(r, dict) and str(r.get("Link", "")).startswith("http")
    ]


# -- api ----------------------------------------------------------------------------------------


def api(client, source):
    """
    Items from a JSON list endpoint. ``collector_config``: ``list_url``, ``items_path`` (dotted
    path to the list, default: the document itself), ``fields`` mapping ``url``/``title``/
    ``published`` to dotted paths inside each item, ``page_param`` and ``max_pages``.
    """
    config = source["collector_config"] or {}
    fields = {
        "url": "url",
        "title": "title",
        "published": "published",
        **(config.get("fields") or {}),
    }
    if not config.get("list_url"):
        raise FetchError(
            f"{source['name']}: api collector needs collector_config.list_url"
        )
    items = []
    for page in range(config.get("max_pages", 1)):
        url = config["list_url"]
        if config.get("page_param"):
            url += ("&" if "?" in url else "?") + f"{config['page_param']}={page + 1}"
        data = _dot(json.loads(client.get(url).content), config.get("items_path"))
        if not data:
            break
        for record in data:
            link = _dot(record, fields["url"])
            if isinstance(link, str) and link.startswith("http"):
                items.append(
                    Item(
                        link,
                        _dot(record, fields["title"]),
                        parse_date(_dot(record, fields["published"])),
                    )
                )
    return items


COLLECTORS = {"rss": rss, "sitemap": sitemap, "github_repo": github_repo, "api": api}
