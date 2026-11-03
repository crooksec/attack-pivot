"""
Polite HTTP client for collectors (SPEC §6.2): robots.txt, per-host rate limit, descriptive user
agent, and no attempt to get past a paywall, login, or bot challenge.
"""

import logging
import os
import time
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "attack-pivot-collector/0.1 (+https://github.com/crooksec/attack-pivot; "
    "public threat-report research; honours robots.txt)"
)
MAX_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_RETRIES = 2
MAX_RETRY_WAIT = 60.0
# Responses that mean "you may not read this": never retried, never worked around.
DENIED = {401, 402, 403, 407, 451}


class FetchError(RuntimeError):
    """A request failed for a reason that is not a policy refusal."""


class RobotsDisallowed(FetchError):
    """robots.txt (or its absence of a usable answer) forbids fetching the URL."""


class AccessDenied(FetchError):
    """The server refused access (login, paywall, bot challenge). We stop; we do not bypass."""


class PoliteClient:
    """
    :param float min_interval: Seconds between requests to one host (raised to the host's
        robots.txt ``Crawl-delay`` when that is larger).
    :param transport: Optional ``httpx`` transport (tests pass a mock).
    :param clock, sleep: Injectable time functions for tests.
    """

    def __init__(
        self,
        min_interval=5.0,
        user_agent=None,
        transport=None,
        clock=time.monotonic,
        sleep=time.sleep,
        timeout=30.0,
    ):
        self.user_agent = (
            user_agent or os.environ.get("PIVOT_USER_AGENT") or DEFAULT_USER_AGENT
        )
        self.min_interval = min_interval
        self._clock, self._sleep = clock, sleep
        self._http = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
        )
        self._robots = (
            {}
        )  # origin -> RobotFileParser | None (None: everything disallowed)
        self._next_allowed = {}  # host -> monotonic time
        self.requests = 0

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- robots.txt ---------------------------------------------------------------------------

    def _origin(self, url):
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    def _load_robots(self, origin):
        """
        Fetch and parse ``/robots.txt``. Per RFC 9309 a missing file (404/410) allows everything;
        any other failure (403, 5xx, network) is treated as "disallow all" so we fail closed.
        """
        try:
            response = self._send(f"{origin}/robots.txt", check_robots=False)
        except AccessDenied:
            logger.warning(
                "robots.txt at %s refused access: treating as disallow-all", origin
            )
            return None
        except FetchError as e:
            logger.warning(
                "robots.txt at %s unavailable (%s): treating as disallow-all", origin, e
            )
            return None
        parser = RobotFileParser()
        if response.status_code in (404, 410):
            parser.parse([])
        elif response.status_code == 200:
            parser.parse(response.text.splitlines())
        else:
            logger.warning(
                "robots.txt at %s returned %s: treating as disallow-all",
                origin,
                response.status_code,
            )
            return None
        return parser

    def robots(self, url):
        origin = self._origin(url)
        if origin not in self._robots:
            self._robots[origin] = self._load_robots(origin)
        return self._robots[origin]

    def allowed(self, url):
        parser = self.robots(url)
        return parser is not None and parser.can_fetch(self.user_agent, url)

    def sitemaps(self, url):
        """``Sitemap:`` lines from the origin's robots.txt."""
        parser = self.robots(url)
        return list(parser.site_maps() or []) if parser else []

    def _interval(self, url):
        parser = self._robots.get(self._origin(url))
        delay = parser.crawl_delay(self.user_agent) if parser else None
        return max(self.min_interval, float(delay or 0))

    # -- requests -----------------------------------------------------------------------------

    def _throttle(self, url):
        host = urlsplit(url).netloc
        now = self._clock()
        wait = self._next_allowed.get(host, 0.0) - now
        if wait > 0:
            self._sleep(wait)
            now = self._clock()
        self._next_allowed[host] = now + self._interval(url)

    def _send(self, url, check_robots=True):
        """One logical GET: robots check, throttling, manual redirects and bounded retries."""
        for _hop in range(MAX_REDIRECTS + 1):
            if check_robots and not self.allowed(url):
                raise RobotsDisallowed(f"robots.txt disallows {url}")
            response = self._get_with_retries(url)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    raise FetchError(f"redirect without Location from {url}")
                url = urljoin(url, location)
                continue
            return response
        raise FetchError(f"too many redirects fetching {url}")

    def _get_with_retries(self, url):
        for attempt in range(MAX_RETRIES + 1):
            self._throttle(url)
            self.requests += 1
            try:
                with self._http.stream("GET", url) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BYTES:
                            raise FetchError(f"{url} is larger than {MAX_BYTES} bytes")
                    status, headers = response.status_code, response.headers
            except httpx.HTTPError as e:
                raise FetchError(f"{url}: {e}") from e
            if status in DENIED:
                raise AccessDenied(f"{url} returned {status}")
            if status in (429, 503) and attempt < MAX_RETRIES:
                wait = _retry_after(headers.get("retry-after"))
                self._sleep(min(wait, MAX_RETRY_WAIT))
                continue
            return httpx.Response(
                status, headers=headers, content=bytes(body), request=response.request
            )
        raise FetchError(f"{url}: gave up after {MAX_RETRIES + 1} attempts")

    def get(self, url):
        """
        GET a URL politely.

        :return: The response (status 2xx).
        :raises RobotsDisallowed: robots.txt forbids it.
        :raises AccessDenied: 401/402/403/407/451.
        :raises FetchError: any other failure, including non-2xx.
        """
        response = self._send(url)
        if not response.is_success:
            raise FetchError(f"{url} returned {response.status_code}")
        return response


def _retry_after(value, default=5.0):
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return default
