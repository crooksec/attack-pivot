"""
Stored secrets: encrypted in ``pivot.secret``, written but never read back through the API.

A secret resolves from the stored value first, then from the process environment (shown as
"from deployment"). Nothing is copied from the environment into the database.
"""

import os
from dataclasses import dataclass

from cryptography.fernet import InvalidToken

from attack_pivot.settings import keystore


@dataclass(frozen=True)
class KnownSecret:
    name: str
    label: str
    purpose: str


KNOWN = {
    s.name: s
    for s in (
        KnownSecret(
            "SERPER_API_KEY",
            "Serper",
            "Web search (google.serper.dev) for finding report URLs",
        ),
        KnownSecret(
            "BRAVE_API_KEY",
            "Brave Search",
            "Web search (api.search.brave.com) for finding report URLs",
        ),
    )
}


def _check_name(name):
    if name not in KNOWN:
        raise ValueError(f"unknown secret {name!r}")


def set_secret(conn, name, value):
    _check_name(name)
    value = (value or "").strip()
    if not value:
        raise ValueError("secret value is empty")
    token = keystore.fernet(create=True).encrypt(value.encode())
    conn.execute(
        "INSERT INTO pivot.secret (name, ciphertext) VALUES (%s, %s) "
        "ON CONFLICT (name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()",
        (name, token),
    )
    conn.commit()


def delete_secret(conn, name):
    _check_name(name)
    deleted = conn.execute("DELETE FROM pivot.secret WHERE name = %s", (name,)).rowcount
    conn.commit()
    return bool(deleted)


def _stored(conn, name):
    row = conn.execute(
        "SELECT ciphertext FROM pivot.secret WHERE name = %s", (name,)
    ).fetchone()
    if row is None:
        return None
    try:
        return keystore.fernet().decrypt(bytes(row["ciphertext"])).decode()
    except (InvalidToken, RuntimeError):
        # Wrong or missing master key: treat as not stored rather than leaking why.
        return None


def resolve(conn, name):
    """The secret's value (stored, else environment), or ``None``. For server-side use only."""
    _check_name(name)
    return _stored(conn, name) or os.environ.get(name) or None


def all_values(conn):
    """Every known secret value currently resolvable, for redaction."""
    return [v for v in (resolve(conn, n) for n in KNOWN) if v]


def status(conn):
    """
    Where each known secret comes from, never its value.

    ``source`` is ``stored``, ``environment`` or ``missing``; ``unreadable`` flags a stored value
    the current master key cannot decrypt.
    """
    stored = {
        r["name"]: r["updated_at"]
        for r in conn.execute("SELECT name, updated_at FROM pivot.secret")
    }
    out = []
    for secret in KNOWN.values():
        readable = secret.name in stored and _stored(conn, secret.name) is not None
        if readable:
            source = "stored"
        elif os.environ.get(secret.name):
            source = "environment"
        else:
            source = "missing"
        out.append(
            {
                "name": secret.name,
                "label": secret.label,
                "purpose": secret.purpose,
                "source": source,
                "unreadable": secret.name in stored and not readable,
                "updated_at": stored.get(secret.name),
            }
        )
    return out
