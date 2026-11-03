import json
from datetime import date

import httpx
import pytest

from attack_pivot.cli import main
from attack_pivot.collect import collectors, registry, run, store
from attack_pivot.collect.http import PoliteClient
from attack_pivot.collect.text import canonical_url, extract_text
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations

BODY = " ".join(f"The actor then ran step {i} on the host." for i in range(40))


def page(title="T"):
    return f"<html><body><nav>menu</nav><article><h1>{title}</h1><p>{BODY}</p></article></body></html>".encode()


def make_client(routes):
    def handler(request):
        url = str(request.url)
        if url.endswith("/robots.txt") and url not in routes:
            return httpx.Response(404)
        status, headers, body = routes.get(url, (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)

    return PoliteClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)


def source(collector, base="https://a.example/blog/", **config):
    return {
        "name": "S",
        "id": None,
        "collector": collector,
        "base_url": base,
        "collector_config": config,
        "default_tlp": "clear",
    }


RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>One</title><link>https://a.example/blog/one?utm_source=rss</link><pubDate>Mon, 02 Mar 2026 10:00:00 GMT</pubDate></item>
<item><title>Two</title><link>/blog/two</link><pubDate>Tue, 03 Feb 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_canonical_url():
    assert (
        canonical_url("HTTPS://A.Example:443/x//y/?b=2&utm_campaign=z&a=1#frag")
        == "https://a.example/x/y?a=1&b=2"
    )
    assert canonical_url("https://a.example") == "https://a.example/"


def test_extract_text_html_text_pdf_free_of_page_chrome():
    text = extract_text(page("Title"), "text/html")
    assert "Title" in text and "step 3" in text and "menu" not in text
    assert (
        extract_text(b"plain  words\n\n\n\nmore", "text/plain")
        == "plain  words\n\nmore"
    )


def test_rss_with_feed_autodiscovery():
    html = b'<html><head><link rel="alternate" type="application/rss+xml" href="/feed.xml"></head></html>'
    c = make_client(
        {
            "https://a.example/blog/": (200, {}, html),
            "https://a.example/feed.xml": (200, {}, RSS),
        }
    )
    items = collectors.rss(c, source("rss"))
    assert [(i.url, i.title, i.published) for i in items] == [
        ("https://a.example/blog/one?utm_source=rss", "One", date(2026, 3, 2)),
        ("https://a.example/blog/two", "Two", date(2026, 2, 3)),
    ]


def test_rss_without_a_feed_is_an_error():
    c = make_client({"https://a.example/blog/": (200, {}, b"<html></html>")})
    with pytest.raises(collectors.FetchError, match="no RSS"):
        collectors.rss(c, source("rss"))


def test_sitemap_index_pattern_and_lastmod():
    index = b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://a.example/sm1.xml</loc></sitemap></sitemapindex>'
    urlset = b"""<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://a.example/csa/one</loc><lastmod>2026-01-05T00:00:00Z</lastmod></url>
<url><loc>https://a.example/about</loc></url></urlset>"""
    c = make_client(
        {
            "https://a.example/robots.txt": (
                200,
                {},
                b"Sitemap: https://a.example/sm.xml\n",
            ),
            "https://a.example/sm.xml": (200, {}, index),
            "https://a.example/sm1.xml": (200, {}, urlset),
        }
    )
    items = collectors.sitemap(c, source("sitemap", url_pattern="/csa/"))
    assert items == [
        collectors.Item("https://a.example/csa/one", None, date(2026, 1, 5))
    ]


def test_github_repo_index_and_api_collector():
    aptnotes = json.dumps(
        [
            {"Title": "R1", "Link": "https://x.example/r1.pdf", "Date": "2014-05-01"},
            {"Title": "bad", "Link": "ftp://x"},
        ]
    ).encode()
    c = make_client(
        {
            "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json": (
                200,
                {},
                aptnotes,
            ),
            "https://api.example/v1/reports?page=1": (
                200,
                {},
                json.dumps(
                    {
                        "data": [
                            {"u": "https://r.example/1", "t": "A", "d": "2025-12-01"}
                        ]
                    }
                ).encode(),
            ),
            "https://api.example/v1/reports?page=2": (200, {}, b'{"data": []}'),
        }
    )
    apt = source(
        "github_repo",
        base="https://github.com/aptnotes/data",
        index_file="APTnotes.json",
    )
    assert collectors.github_repo(c, apt) == [
        collectors.Item("https://x.example/r1.pdf", "R1", date(2014, 5, 1))
    ]
    api = source(
        "api",
        list_url="https://api.example/v1/reports",
        items_path="data",
        fields={"url": "u", "title": "t", "published": "d"},
        page_param="page",
        max_pages=3,
    )
    assert collectors.api(c, api) == [
        collectors.Item("https://r.example/1", "A", date(2025, 12, 1))
    ]


@pytest.fixture
def db(scratch_db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        registry.load(
            conn,
            [
                {
                    "name": "Blog",
                    "publisher": None,
                    "source_class": "vendor",
                    "base_url": "https://a.example/blog/",
                    "collector": "rss",
                    "collector_config": {
                        "feed_url": "https://a.example/feed.xml",
                        "rate_limit_seconds": 5,
                    },
                    "default_tlp": "clear",
                    "licence": "CC BY 4.0",
                    "reliability": "B",
                    "notes": None,
                    "enabled": False,
                }
            ],
        )
        yield conn


ROUTES = {
    "https://a.example/feed.xml": (200, {}, RSS),
    "https://a.example/blog/one?utm_source=rss": (
        200,
        {"content-type": "text/html"},
        page("One"),
    ),
    "https://a.example/blog/one": (200, {"content-type": "text/html"}, page("One")),
    "https://a.example/blog/two": (200, {"content-type": "text/html"}, page("Two")),
}


def src(conn, name="Blog"):
    return conn.execute(
        "SELECT * FROM pivot.source WHERE name = %s", (name,)
    ).fetchone()


@pytest.mark.pivot_db
def test_disabled_source_is_refused(db):
    with pytest.raises(RuntimeError, match="not enabled"):
        run.get_source(db, "Blog")
    assert run.enabled_collectable(db) == []
    registry.enable(db, "Blog", "me")
    assert run.get_source(db, "Blog")["enabled"]
    assert [s["name"] for s in run.enabled_collectable(db)] == ["Blog"]


@pytest.mark.pivot_db
def test_collect_stores_text_locally_and_dedupes(db, tmp_path):
    s = src(db)
    stats = run.collect_source(db, s, make_client(ROUTES))
    assert (stats["discovered"], stats["new"]) == (2, 2)
    rows = db.execute(
        "SELECT url, title, published_at, tlp, triage_status, text_path, sha256 FROM pivot.report ORDER BY title"
    ).fetchall()
    assert [
        (r["url"], r["published_at"], r["tlp"], r["triage_status"]) for r in rows
    ] == [
        ("https://a.example/blog/one", date(2026, 3, 2), "clear", "new"),
        ("https://a.example/blog/two", date(2026, 2, 3), "clear", "new"),
    ]
    stored = (
        tmp_path / "data" / "pivot" / "reports" / f"{rows[0]['sha256']}.txt"
    ).read_text()
    assert "step 3" in stored and "menu" not in stored
    # second run: nothing new; same page under a different URL is caught by sha256
    again = run.collect_source(db, s, make_client(ROUTES))
    assert again["new"] == 0 and again["duplicate_url"] == 2
    routes = {**ROUTES, "https://a.example/blog/two": (200, {}, page("One"))}
    db.execute("DELETE FROM pivot.report WHERE title = 'Two'")
    db.commit()
    assert run.collect_source(db, s, make_client(routes))["duplicate_sha256"] == 1


@pytest.mark.pivot_db
def test_since_limit_and_failures_are_counted(db):
    s = src(db)
    assert run.collect_source(
        db, s, make_client(ROUTES), since=date(2026, 3, 1)
    ).items() >= {
        ("new", 1),
        ("old", 1),
    }
    db.execute("DELETE FROM pivot.report")
    db.commit()
    assert run.collect_source(db, s, make_client(ROUTES), limit=1)["new"] == 1
    denied = {
        **ROUTES,
        "https://a.example/blog/two": (403, {}, b"blocked"),
        "https://a.example/robots.txt": (
            200,
            {},
            b"User-agent: *\nDisallow: /blog/one\n",
        ),
    }
    db.execute("DELETE FROM pivot.report")
    db.commit()
    stats = run.collect_source(db, s, make_client(denied))
    assert (stats["robots_disallowed"], stats["access_denied"], stats["new"]) == (
        1,
        1,
        0,
    )
    short = {**ROUTES, "https://a.example/blog/two": (200, {}, b"<p>tiny</p>")}
    assert run.collect_source(db, s, make_client(short))["too_short"] == 1


@pytest.mark.pivot_db
def test_discovery_failure_is_reported_not_raised(db):
    stats = run.collect_source(
        db, src(db), make_client({"https://a.example/feed.xml": (500, {}, b"")})
    )
    assert stats["discovery_failed"] == 1 and stats["new"] == 0


@pytest.mark.pivot_db
def test_import_files_and_url_list(db, tmp_path):
    (tmp_path / "r.txt").write_text(BODY)
    (tmp_path / "tiny.txt").write_text("short")
    (tmp_path / "urls.txt").write_text(
        "# list\nhttps://a.example/blog/two  # trailing\n\n"
    )
    s = src(db)
    stats = run.import_files(
        db, s, [tmp_path / "r.txt", tmp_path / "tiny.txt"], tlp="green"
    )
    assert (stats["new"], stats["too_short"]) == (1, 1)
    assert db.execute("SELECT tlp, url FROM pivot.report").fetchone() == {
        "tlp": "green",
        "url": None,
    }
    assert run.import_files(db, s, [tmp_path / "r.txt"])["duplicate_sha256"] == 1
    items = run.read_url_list(tmp_path / "urls.txt")
    assert [i.url for i in items] == ["https://a.example/blog/two"]
    assert run.collect_source(db, s, make_client(ROUTES), items=items)["new"] == 1


@pytest.mark.pivot_db
def test_isac_import_requires_a_tlp(db, tmp_path):
    db.execute(
        "INSERT INTO pivot.source (name, source_class, collector, default_tlp) VALUES ('I', 'isac', 'manual', 'amber')"
    )
    db.commit()
    (tmp_path / "r.txt").write_text(BODY)
    with pytest.raises(RuntimeError, match="--tlp"):
        run.import_files(db, src(db, "I"), [tmp_path / "r.txt"])
    run.import_files(db, src(db, "I"), [tmp_path / "r.txt"], tlp="amber+strict")
    assert (
        db.execute("SELECT tlp FROM pivot.report").fetchone()["tlp"] == "amber+strict"
    )


@pytest.mark.pivot_db
def test_unique_url_index(db):
    store.save_report(db, src(db), text=BODY, url="https://a.example/x?utm_source=1")
    _, reason = store.save_report(
        db, src(db), text=BODY + " different", url="https://a.example/x/"
    )
    assert reason == "url"


@pytest.mark.pivot_db
def test_cli_collect_refuses_a_disabled_source(scratch_db_url, capsys):
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    assert main([*url, "sources", "load"]) == 0
    assert main([*url, "collect", "--source", "The DFIR Report"]) == 1
    assert "not enabled" in capsys.readouterr().err
    assert main([*url, "collect"]) == 0
    assert "no enabled network sources" in capsys.readouterr().out
