import logging

import pytest

from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.settings import keystore, options, redact, secrets

KEY = "sk-test-0123456789abcdefSECRET"


@pytest.fixture(autouse=True)
def key_file(tmp_path, monkeypatch):
    monkeypatch.delenv("PIVOT_SECRET_KEY", raising=False)
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    monkeypatch.setenv("PIVOT_SECRET_KEY_FILE", str(tmp_path / "keys" / "secret.key"))
    redact.forget_all()
    yield tmp_path / "keys" / "secret.key"
    redact.forget_all()


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        yield conn


def test_reading_never_creates_the_key(key_file):
    with pytest.raises(RuntimeError, match="no secret key"):
        keystore.load_key()
    assert not key_file.exists()


def test_key_is_created_once_private_and_never_overwritten(key_file):
    first = keystore.load_key(create=True)
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert (key_file.parent / ".gitignore").read_text().startswith("*")
    assert keystore.load_key(create=True) == first == keystore.load_key()


def test_environment_key_wins_and_creates_no_file(key_file, monkeypatch):
    from cryptography.fernet import Fernet

    env_key = Fernet.generate_key().decode()
    monkeypatch.setenv("PIVOT_SECRET_KEY", env_key)
    assert keystore.load_key(create=True) == env_key.encode()
    assert not key_file.exists()


@pytest.mark.pivot_db
def test_secret_is_encrypted_at_rest_and_resolves(db):
    secrets.set_secret(db, "SERPER_API_KEY", KEY)
    ciphertext = bytes(
        db.execute("SELECT ciphertext FROM pivot.secret").fetchone()["ciphertext"]
    )
    assert KEY.encode() not in ciphertext
    assert secrets.resolve(db, "SERPER_API_KEY") == KEY
    assert secrets.resolve(db, "BRAVE_API_KEY") is None


@pytest.mark.pivot_db
def test_stored_value_beats_environment_and_environment_is_labelled(db, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "from-env-value")
    monkeypatch.setenv("SERPER_API_KEY", "env-serper-value")
    secrets.set_secret(db, "SERPER_API_KEY", KEY)
    assert secrets.resolve(db, "SERPER_API_KEY") == KEY
    assert secrets.resolve(db, "BRAVE_API_KEY") == "from-env-value"
    by_name = {s["name"]: s for s in secrets.status(db)}
    assert by_name["SERPER_API_KEY"]["source"] == "stored"
    assert by_name["BRAVE_API_KEY"]["source"] == "environment"
    assert not any(
        KEY in str(s) or "from-env-value" in str(s) for s in secrets.status(db)
    )


@pytest.mark.pivot_db
def test_delete_and_unknown_names(db):
    secrets.set_secret(db, "SERPER_API_KEY", KEY)
    assert secrets.delete_secret(db, "SERPER_API_KEY") is True
    assert secrets.delete_secret(db, "SERPER_API_KEY") is False
    with pytest.raises(ValueError, match="unknown secret"):
        secrets.set_secret(db, "OTHER", KEY)
    with pytest.raises(ValueError, match="empty"):
        secrets.set_secret(db, "SERPER_API_KEY", "   ")


@pytest.mark.pivot_db
def test_a_lost_master_key_reads_as_unreadable_not_as_an_error(db, key_file):
    secrets.set_secret(db, "SERPER_API_KEY", KEY)
    key_file.unlink()
    keystore.load_key(create=True)  # a new, different key
    assert secrets.resolve(db, "SERPER_API_KEY") is None
    status = {s["name"]: s for s in secrets.status(db)}["SERPER_API_KEY"]
    assert status["source"] == "missing" and status["unreadable"] is True


@pytest.mark.pivot_db
def test_options_default_validate_and_reset(db):
    assert options.get(db, "search.provider") == "off"
    assert options.set_value(db, "search.provider", "both") == "both"
    assert options.set_value(db, "search.results_per_query", "15") == 15
    assert options.get(db, "search.results_per_query") == 15
    for key, bad in (
        ("search.provider", "bing"),
        ("search.results_per_query", 0),
        ("search.results_per_query", "x"),
        ("search.budget.brave", -1),
    ):
        with pytest.raises(ValueError):
            options.set_value(db, key, bad)
    with pytest.raises(ValueError, match="unknown setting"):
        options.set_value(db, "nope", 1)
    rows = {o["key"]: o for o in options.list_all(db)}
    assert rows["search.provider"]["is_default"] is False
    options.reset(db, "search.provider")
    assert options.get(db, "search.provider") == "off"


def test_redact_removes_registered_values_and_key_shaped_text():
    redact.register([KEY])
    assert KEY not in redact.redact(f"failed with {KEY} inside")
    assert "abcdef0123456789" not in redact.redact("X-API-KEY: abcdef0123456789")
    assert "tokentokentokentoken" not in redact.redact("Bearer tokentokentokentoken")
    assert redact.redact("nothing here") == "nothing here"


def test_log_filter_scrubs_formatted_messages(caplog):
    redact.register([KEY])
    redact.install_log_filter()
    with caplog.at_level(logging.WARNING):
        logging.getLogger("attack_pivot.test").warning("request with %s failed", KEY)
    assert KEY not in caplog.text and "[redacted]" in caplog.text
