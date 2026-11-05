import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from attack_pivot.api.settings import router  # noqa: E402
from attack_pivot.db import connect  # noqa: E402
from attack_pivot.db import migrate as migrations  # noqa: E402
from attack_pivot.settings import redact  # noqa: E402

KEY = "serper-key-0123456789abcdef"
TOKEN = "admin-token-for-tests"
H = {"X-Pivot-Admin-Token": TOKEN}

pytestmark = pytest.mark.pivot_db


@pytest.fixture
def client(scratch_db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("PIVOT_DATABASE_URL", scratch_db_url)
    monkeypatch.setenv("PIVOT_SECRET_KEY_FILE", str(tmp_path / "k" / "secret.key"))
    monkeypatch.delenv("PIVOT_SECRET_KEY", raising=False)
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    monkeypatch.setenv("PIVOT_ADMIN_TOKEN", TOKEN)
    redact.forget_all()
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return TestClient(app)


def test_fails_closed_without_a_configured_token(client, monkeypatch):
    monkeypatch.delenv("PIVOT_ADMIN_TOKEN")
    for call in (
        lambda: client.get("/api/v1/pivot/settings", headers=H),
        lambda: client.put(
            "/api/v1/pivot/settings/secrets/SERPER_API_KEY",
            json={"value": KEY},
            headers=H,
        ),
    ):
        assert call().status_code == 403


def test_rejects_a_missing_or_wrong_token(client):
    assert client.get("/api/v1/pivot/settings").status_code == 403
    bad = {"X-Pivot-Admin-Token": "nope"}
    assert client.get("/api/v1/pivot/settings", headers=bad).status_code == 403
    assert (
        client.put(
            "/api/v1/pivot/settings/secrets/SERPER_API_KEY",
            json={"value": KEY},
            headers=bad,
        ).status_code
        == 403
    )


def test_read_lists_options_and_secret_status(client):
    body = client.get("/api/v1/pivot/settings", headers=H).json()
    assert {o["key"] for o in body["options"]} >= {
        "search.provider",
        "search.budget.serper",
    }
    assert {s["name"]: s["source"] for s in body["secrets"]} == {
        "SERPER_API_KEY": "missing",
        "BRAVE_API_KEY": "missing",
    }


def test_secret_is_write_only(client):
    put = client.put(
        "/api/v1/pivot/settings/secrets/SERPER_API_KEY", json={"value": KEY}, headers=H
    )
    assert put.status_code == 200
    assert {s["name"]: s["source"] for s in put.json()["secrets"]}[
        "SERPER_API_KEY"
    ] == "stored"
    for response in (
        put,
        client.get("/api/v1/pivot/settings", headers=H),
        client.delete("/api/v1/pivot/settings/secrets/BRAVE_API_KEY", headers=H),
    ):
        assert KEY not in response.text
    assert (
        client.put(
            "/api/v1/pivot/settings/secrets/SERPER_API_KEY",
            json={"value": "  "},
            headers=H,
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/v1/pivot/settings/secrets/OTHER", json={"value": KEY}, headers=H
        ).status_code
        == 422
    )
    gone = client.delete("/api/v1/pivot/settings/secrets/SERPER_API_KEY", headers=H)
    assert {s["name"]: s["source"] for s in gone.json()["secrets"]}[
        "SERPER_API_KEY"
    ] == "missing"


def test_options_validate_and_reset(client):
    ok = client.put(
        "/api/v1/pivot/settings/options/search.provider",
        json={"value": "brave"},
        headers=H,
    )
    assert {o["key"]: o["value"] for o in ok.json()["options"]}[
        "search.provider"
    ] == "brave"
    bad = client.put(
        "/api/v1/pivot/settings/options/search.provider",
        json={"value": "bing"},
        headers=H,
    )
    assert bad.status_code == 422
    assert (
        client.put(
            "/api/v1/pivot/settings/options/nope", json={"value": 1}, headers=H
        ).status_code
        == 422
    )
    reset = client.delete("/api/v1/pivot/settings/options/search.provider", headers=H)
    assert {o["key"]: o["value"] for o in reset.json()["options"]}[
        "search.provider"
    ] == "off"
