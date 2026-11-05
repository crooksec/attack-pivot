"""Serper and Brave Search clients. Each takes an ``httpx.Client`` so tests can mock the transport."""

from dataclasses import dataclass

import httpx

from attack_pivot.settings.redact import redact

SERPER_URL = "https://google.serper.dev/search"
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"

SERPER_FRESHNESS = {"day": "qdr:d", "week": "qdr:w", "month": "qdr:m", "year": "qdr:y"}
BRAVE_FRESHNESS = {"day": "pd", "week": "pw", "month": "pm", "year": "py"}

TIMEOUT = 20.0


class SearchError(RuntimeError):
    """A provider call failed. The message never contains a key."""


@dataclass(frozen=True)
class Hit:
    url: str
    title: str | None
    snippet: str | None
    provider: str
    rank: int


def _get_json(call, api_key, provider):
    try:
        response = call()
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as e:
        raise SearchError(f"{provider}: HTTP {e.response.status_code}") from None
    except (httpx.HTTPError, ValueError) as e:
        raise SearchError(f"{provider}: {redact(e, [api_key])}") from None


def serper(http, api_key, query, num=10, freshness="any"):
    body = {"q": query, "num": num}
    if freshness in SERPER_FRESHNESS:
        body["tbs"] = SERPER_FRESHNESS[freshness]
    data = _get_json(
        lambda: http.post(
            SERPER_URL,
            json=body,
            headers={"X-API-KEY": api_key},
            timeout=TIMEOUT,
        ),
        api_key,
        "serper",
    )
    return [
        Hit(r["link"], r.get("title"), r.get("snippet"), "serper", i)
        for i, r in enumerate(data.get("organic") or [], start=1)
        if r.get("link")
    ]


def brave(http, api_key, query, num=10, freshness="any"):
    params = {"q": query, "count": num}
    if freshness in BRAVE_FRESHNESS:
        params["freshness"] = BRAVE_FRESHNESS[freshness]
    data = _get_json(
        lambda: http.get(
            BRAVE_URL,
            params=params,
            headers={
                "X-Subscription-Token": api_key,
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        ),
        api_key,
        "brave",
    )
    return [
        Hit(r["url"], r.get("title"), r.get("description"), "brave", i)
        for i, r in enumerate((data.get("web") or {}).get("results") or [], start=1)
        if r.get("url")
    ]


PROVIDERS = {"serper": ("SERPER_API_KEY", serper), "brave": ("BRAVE_API_KEY", brave)}
