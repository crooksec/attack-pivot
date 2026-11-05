import json
import logging

import httpx
import pytest

from attack_pivot.cli import main
from attack_pivot.collect import registry
from attack_pivot.collect.http import PoliteClient
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.search import discovery, providers
from attack_pivot.settings import options, redact, secrets

SERPER_KEY = "serper-key-0123456789abcdef"
BRAVE_KEY = "brave-key-0123456789abcdef"
BODY = " ".join(f"The actor then ran step {i} on the host." for i in range(40))
PAGE = f"<html><body><article><h1>T</h1><p>{BODY}</p></article></body></html>".encode()


def serper_reply(request):
    body = json.loads(request.content)
    assert request.headers["x-api-key"] == SERPER_KEY
    assert body["q"] == "lazarus intrusion" and body["num"] == 10
    return httpx.Response(
        200,
        json={
            "organic": [
                {"title": "One", "link": "https://a.example/blog/one", "snippet": "s1"},
                {"title": "Two", "link": "https://b.example/post", "snippet": "s2"},
                {"title": "No link"},
            ]
        },
    )


def brave_reply(request):
    assert request.headers["x-subscription-token"] == BRAVE_KEY
    assert request.url.params["q"] == "lazarus intrusion"
    return httpx.Response(
        200,
        json={
            "web": {
                "results": [
                    {
                        "title": "One again",
                        "url": "https://a.example/blog/one?utm_source=x",
                        "description": "d",
                    },
                    {
                        "title": "Three",
                        "url": "https://c.example/p",
                        "description": "d3",
                    },
                ]
            }
        },
    )


def mock_http():
    def handler(request):
        if request.url.host == "google.serper.dev":
            return serper_reply(request)
        return brave_reply(request)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_serper_request_and_parsing():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return serper_reply(request)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    hits = providers.serper(http, SERPER_KEY, "lazarus intrusion", 10, "week")
    assert seen["body"] == {"q": "lazarus intrusion", "num": 10, "tbs": "qdr:w"}
    assert [(h.url, h.rank, h.provider) for h in hits] == [
        ("https://a.example/blog/one", 1, "serper"),
        ("https://b.example/post", 2, "serper"),
    ]


def test_brave_request_and_parsing():
    seen = {}

    def handler(request):
        seen["params"] = dict(request.url.params)
        return brave_reply(request)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    hits = providers.brave(http, BRAVE_KEY, "lazarus intrusion", 7, "month")
    assert seen["params"] == {"q": "lazarus intrusion", "count": "7", "freshness": "pm"}
    assert [h.url for h in hits][1] == "https://c.example/p"


def test_http_errors_become_search_errors_without_the_key():
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    with pytest.raises(providers.SearchError, match="HTTP 429") as err:
        providers.serper(http, SERPER_KEY, "q")
    assert SERPER_KEY not in str(err.value)

    def boom(request):
        raise httpx.ConnectError(f"cannot reach host with {SERPER_KEY}")

    http = httpx.Client(transport=httpx.MockTransport(boom))
    redact.register([SERPER_KEY])
    with pytest.raises(providers.SearchError) as err:
        providers.serper(http, SERPER_KEY, "q")
    assert SERPER_KEY not in str(err.value)


@pytest.fixture
def db(scratch_db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PIVOT_SECRET_KEY_FILE", str(tmp_path / "keys" / "secret.key"))
    monkeypatch.delenv("PIVOT_SECRET_KEY", raising=False)
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    redact.forget_all()
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
                    "collector_config": {"rate_limit_seconds": 5},
                    "default_tlp": "clear",
                    "licence": "CC BY 4.0",
                    "reliability": "B",
                    "notes": None,
                    "enabled": False,
                }
            ],
        )
        yield conn
    redact.forget_all()


def configure(db, provider="both"):
    secrets.set_secret(db, "SERPER_API_KEY", SERPER_KEY)
    secrets.set_secret(db, "BRAVE_API_KEY", BRAVE_KEY)
    options.set_value(db, "search.provider", provider)


@pytest.mark.pivot_db
def test_search_is_off_by_default(db):
    with pytest.raises(RuntimeError, match="search is off"):
        discovery.search(db, "x", http=mock_http())


@pytest.mark.pivot_db
def test_both_providers_merge_and_dedupe_by_canonical_url(db):
    configure(db)
    stats = discovery.search(db, "lazarus intrusion", http=mock_http())
    assert (stats["queries"], stats["results"], stats["queued"]) == (2, 4, 3)
    urls = sorted(r["canonical_url"] for r in discovery.queue(db))
    assert urls == [
        "https://a.example/blog/one",
        "https://b.example/post",
        "https://c.example/p",
    ]
    assert discovery.used(db, "serper") == discovery.used(db, "brave") == 1
    again = discovery.search(db, "lazarus intrusion", http=mock_http())
    assert again["queued"] == 0 and again["already_queued"] == 3


@pytest.mark.pivot_db
def test_missing_key_and_budget_stop_the_call(db):
    options.set_value(db, "search.provider", "serper")
    stats = discovery.search(db, "lazarus intrusion", http=mock_http())
    assert stats["no_key"] == 1 and stats["queries"] == 0

    secrets.set_secret(db, "SERPER_API_KEY", SERPER_KEY)
    options.set_value(db, "search.budget.serper", 1)
    assert discovery.search(db, "lazarus intrusion", http=mock_http())["queries"] == 1
    capped = discovery.search(db, "lazarus intrusion", http=mock_http())
    assert capped["over_budget"] == 1 and capped["queries"] == 0


@pytest.mark.pivot_db
def test_environment_key_is_used_when_nothing_is_stored(db, monkeypatch):
    monkeypatch.setenv("SERPER_API_KEY", SERPER_KEY)
    options.set_value(db, "search.provider", "serper")
    assert discovery.search(db, "lazarus intrusion", http=mock_http())["queued"] == 2


@pytest.mark.pivot_db
def test_dry_run_sends_nothing(db, scratch_db_url, capsys, monkeypatch):
    configure(db, "serper")

    def forbidden(*a, **k):
        raise AssertionError("dry run must not build a client")

    monkeypatch.setattr(discovery.httpx, "Client", forbidden)
    assert (
        main(["--database-url", scratch_db_url, "search", "run", "--dry-run", "x"]) == 0
    )
    out = capsys.readouterr().out
    assert "serper: key set, 0/100" in out and "nothing sent" in out
    assert SERPER_KEY not in out


def polite(routes):
    def handler(request):
        url = str(request.url)
        if url.endswith("/robots.txt"):
            return httpx.Response(404)
        status, headers, body = routes.get(url, (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)

    return PoliteClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)


@pytest.mark.pivot_db
def test_only_urls_of_an_enabled_mapped_source_are_fetched(db):
    configure(db)
    discovery.search(db, "lazarus intrusion", http=mock_http())
    routes = {
        "https://a.example/blog/one": (200, {"content-type": "text/html"}, PAGE),
        "https://b.example/post": (200, {"content-type": "text/html"}, PAGE),
    }

    # nothing is mapped: nothing is fetched
    stats = discovery.fetch_queued(db, polite(routes))
    assert stats["unmapped"] == 3 and stats["fetched"] == 0

    # mapped but the source is not licence-reviewed: still nothing
    discovery.map_domain(db, "www.A.example", "Blog")
    stats = discovery.fetch_queued(db, polite(routes))
    assert stats["source_disabled"] == 1 and stats["fetched"] == 0
    assert db.execute("SELECT count(*) AS n FROM pivot.report").fetchone()["n"] == 0

    registry.enable(db, "Blog", "me")
    stats = discovery.fetch_queued(db, polite(routes))
    assert stats["fetched"] == 1 and stats["unmapped"] == 2
    row = db.execute(
        "SELECT status, report_id FROM pivot.discovered_url WHERE domain = 'a.example'"
    ).fetchone()
    assert row["status"] == "fetched" and row["report_id"] is not None
    assert discovery.queue(db, "queued")[0]["source"] is None


@pytest.mark.pivot_db
def test_subdomains_match_and_failures_are_recorded(db):
    discovery.map_domain(db, "a.example", "Blog")
    assert discovery.domain_source(db, "deep.sub.a.example")["name"] == "Blog"
    assert discovery.domain_source(db, "nota.example") is None
    registry.enable(db, "Blog", "me")
    db.execute(
        "INSERT INTO pivot.discovered_url (url, canonical_url, domain, provider, query) "
        "VALUES ('https://x.a.example/p', 'https://x.a.example/p', 'x.a.example', 'serper', 'q')"
    )
    db.commit()
    stats = discovery.fetch_queued(
        db, polite({"https://x.a.example/p": (403, {}, b"")})
    )
    assert stats["failed"] == 1
    row = db.execute("SELECT status, note FROM pivot.discovered_url").fetchone()
    assert row["status"] == "failed" and "access_denied" in row["note"]


@pytest.mark.pivot_db
def test_reject_and_map_validation(db):
    configure(db, "serper")
    discovery.search(db, "lazarus intrusion", http=mock_http())
    assert discovery.reject(db, "https://b.example/post") is True
    assert discovery.reject(db, "https://b.example/post") is False
    assert len(discovery.queue(db, "rejected")) == 1
    with pytest.raises(ValueError):
        discovery.map_domain(db, "https://a.example/x", "Blog")
    with pytest.raises(RuntimeError, match="no source named"):
        discovery.map_domain(db, "a.example", "Nope")


@pytest.mark.pivot_db
def test_a_leaking_adapter_cannot_put_a_key_in_logs_errors_or_the_database(
    db, caplog, monkeypatch
):
    """An adapter written to leak its key in its error and its own log line."""
    configure(db, "serper")
    redact.install_log_filter()

    def leaky(http, api_key, query, num, freshness):
        logging.getLogger("attack_pivot.search.leaky").error(
            "calling with key %s", api_key
        )
        raise providers.SearchError(f"serper: rejected key {api_key}")

    monkeypatch.setitem(providers.PROVIDERS, "serper", ("SERPER_API_KEY", leaky))
    with caplog.at_level(logging.DEBUG):
        stats = discovery.search(db, "lazarus intrusion", http=mock_http())
    assert stats["failed"] == 1
    assert SERPER_KEY not in caplog.text
    assert "[redacted]" in caplog.text
    dump = json.dumps(
        [
            dict(r, ciphertext=None, updated_at=str(r.get("updated_at")))
            for t in ("setting", "search_usage", "discovered_url")
            for r in db.execute(f"SELECT * FROM pivot.{t}").fetchall()
        ],
        default=str,
    )
    assert SERPER_KEY not in dump
