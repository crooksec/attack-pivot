import httpx
import pytest

from attack_pivot.collect.http import (
    AccessDenied,
    FetchError,
    PoliteClient,
    RobotsDisallowed,
)

ROBOTS = "User-agent: *\nDisallow: /private/\nSitemap: https://a.example/sm.xml\n"


class Site:
    """A mock web: ``routes`` maps URL -> (status, headers, body); every request is logged."""

    def __init__(self, routes):
        self.routes = routes
        self.log = []

    def __call__(self, request):
        self.log.append(str(request.url))
        status, headers, body = self.routes.get(
            str(request.url), (404, {}, b"not found")
        )
        return httpx.Response(status, headers=headers, content=body)


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def client(routes, interval=5.0):
    site, clock = Site(routes), Clock()
    c = PoliteClient(
        min_interval=interval,
        transport=httpx.MockTransport(site),
        clock=clock,
        sleep=clock.sleep,
    )
    return c, site, clock


PAGE = (200, {"content-type": "text/html"}, b"<p>hello</p>")


def test_robots_disallow_blocks_without_requesting_the_page():
    c, site, _ = client(
        {"https://a.example/robots.txt": (200, {}, ROBOTS.encode()),
         "https://a.example/private/x": PAGE}
    )  # fmt: skip
    with pytest.raises(RobotsDisallowed):
        c.get("https://a.example/private/x")
    assert site.log == ["https://a.example/robots.txt"]


def test_allowed_path_is_fetched_with_a_descriptive_user_agent():
    seen = []

    def handler(request):
        seen.append(request.headers["user-agent"])
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS)
        return httpx.Response(200, text="ok")

    c = PoliteClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)
    assert c.get("https://a.example/public/x").text == "ok"
    assert all("attack-pivot-collector" in ua and "github.com" in ua for ua in seen)
    assert c.sitemaps("https://a.example/") == ["https://a.example/sm.xml"]


def test_robots_is_fetched_once_per_origin():
    c, site, _ = client(
        {"https://a.example/robots.txt": (200, {}, b""),
         "https://a.example/1": PAGE, "https://a.example/2": PAGE}
    )  # fmt: skip
    c.get("https://a.example/1")
    c.get("https://a.example/2")
    assert site.log.count("https://a.example/robots.txt") == 1


def test_rate_limit_spaces_requests_per_host_not_across_hosts():
    c, site, clock = client(
        {
            "https://a.example/robots.txt": (404, {}, b""),
            "https://b.example/robots.txt": (404, {}, b""),
            "https://a.example/1": PAGE,
            "https://a.example/2": PAGE,
            "https://b.example/1": PAGE,
        }
    )
    c.get("https://a.example/1")  # robots + page on a: the page waits 5 s after robots
    c.get("https://a.example/2")
    c.get("https://b.example/1")
    assert clock.sleeps == [5.0, 5.0, 5.0]  # a: robots->1, 1->2; b: robots->1
    assert c.requests == 5


def test_crawl_delay_larger_than_the_default_wins():
    c, _, clock = client(
        {"https://a.example/robots.txt": (200, {}, b"User-agent: *\nCrawl-delay: 20\n"),
         "https://a.example/1": PAGE, "https://a.example/2": PAGE}
    )  # fmt: skip
    c.get("https://a.example/1")
    c.get("https://a.example/2")
    assert clock.sleeps[-1] == 20.0


@pytest.mark.parametrize(
    "status, allowed", [(404, True), (410, True), (403, False), (500, False)]
)
def test_robots_txt_status_handling_fails_closed(status, allowed):
    c, _, _ = client(
        {"https://a.example/robots.txt": (status, {}, b""), "https://a.example/x": PAGE}
    )
    if allowed:
        assert c.get("https://a.example/x").status_code == 200
    else:
        with pytest.raises(RobotsDisallowed):
            c.get("https://a.example/x")


def test_unreachable_robots_txt_fails_closed():
    def boom(request):
        raise httpx.ConnectError("down")

    c = PoliteClient(transport=httpx.MockTransport(boom), sleep=lambda s: None)
    with pytest.raises(RobotsDisallowed):
        c.get("https://a.example/x")


@pytest.mark.parametrize("status", [401, 402, 403, 451])
def test_access_denied_is_not_retried_or_bypassed(status):
    c, site, _ = client(
        {"https://a.example/robots.txt": (404, {}, b""),
         "https://a.example/paywalled": (status, {}, b"Just a moment...")}
    )  # fmt: skip
    with pytest.raises(AccessDenied):
        c.get("https://a.example/paywalled")
    assert site.log.count("https://a.example/paywalled") == 1


def test_429_honours_retry_after_then_succeeds():
    calls = []

    def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "30"})
        return httpx.Response(200, text="ok")

    clock = Clock()
    c = PoliteClient(
        transport=httpx.MockTransport(handler), clock=clock, sleep=clock.sleep
    )
    assert c.get("https://a.example/x").text == "ok"
    assert 30.0 in clock.sleeps


def test_persistent_429_gives_up():
    c, _, _ = client(
        {"https://a.example/robots.txt": (404, {}, b""), "https://a.example/x": (429, {}, b"")}
    )  # fmt: skip
    with pytest.raises(FetchError, match="429"):
        c.get("https://a.example/x")


def test_non_success_status_is_an_error():
    c, _, _ = client({"https://a.example/robots.txt": (404, {}, b"")})
    with pytest.raises(FetchError, match="404"):
        c.get("https://a.example/missing")


def test_redirects_are_followed_but_each_hop_checks_robots():
    c, site, _ = client(
        {
            "https://a.example/robots.txt": (200, {}, ROBOTS.encode()),
            "https://a.example/old": (301, {"location": "/private/new"}, b""),
            "https://a.example/ok": (302, {"location": "/final"}, b""),
            "https://a.example/final": PAGE,
        }
    )
    assert c.get("https://a.example/ok").status_code == 200
    with pytest.raises(RobotsDisallowed):
        c.get("https://a.example/old")
    assert "https://a.example/private/new" not in site.log


def test_redirect_loop_is_cut_off():
    c, _, _ = client(
        {"https://a.example/robots.txt": (404, {}, b""),
         "https://a.example/loop": (302, {"location": "/loop"}, b"")}
    )  # fmt: skip
    with pytest.raises(FetchError, match="redirects"):
        c.get("https://a.example/loop")


def test_oversized_body_is_refused(monkeypatch):
    monkeypatch.setattr("attack_pivot.collect.http.MAX_BYTES", 100)
    c, _, _ = client(
        {"https://a.example/robots.txt": (404, {}, b""),
         "https://a.example/big": (200, {}, b"x" * 500)}
    )  # fmt: skip
    with pytest.raises(FetchError, match="larger"):
        c.get("https://a.example/big")
