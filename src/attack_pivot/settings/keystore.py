"""
The master key that encrypts stored secrets.

The key is never in the database or a dump. It comes from ``PIVOT_SECRET_KEY`` (a Fernet key, for
deployments) or from a local file that is created once and never overwritten. Losing the file loses
only the stored secrets, which are then entered again.
"""

import os
from pathlib import Path

from cryptography.fernet import Fernet


def key_path():
    """``PIVOT_SECRET_KEY_FILE``, else ``DATA_DIR/pivot/secret.key``."""
    explicit = os.environ.get("PIVOT_SECRET_KEY_FILE")
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "secret.key"


def _create(path):
    """Write a new key exclusively (0600); ``FileExistsError`` if another process won the race."""
    path.parent.mkdir(parents=True, exist_ok=True)
    guard = path.parent / ".gitignore"
    if not guard.exists():
        guard.write_text("*\n!.gitignore\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(Fernet.generate_key())


def load_key(create=False):
    """
    The master key as bytes.

    :param bool create: Generate the key file if there is none. Reads never create it, so a
        mistyped path cannot silently orphan the stored secrets.
    :raises RuntimeError: No key, and ``create`` is false.
    """
    env = os.environ.get("PIVOT_SECRET_KEY")
    if env:
        return env.encode()
    path = key_path()
    if not path.exists():
        if not create:
            raise RuntimeError(
                f"no secret key at {path}; storing a secret creates it "
                "(or set PIVOT_SECRET_KEY)"
            )
        try:
            _create(path)
        except FileExistsError:
            pass
    return path.read_bytes().strip()


def fernet(create=False):
    return Fernet(load_key(create))
