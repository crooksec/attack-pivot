"""
Settings API: options and stored secrets, for the Explorer's Settings page.

Fails closed: every route needs ``X-Pivot-Admin-Token`` to match ``PIVOT_ADMIN_TOKEN``, and with no
token configured every route answers 403. Secrets are write-only: no route returns a value.
"""

import hmac
import os

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from attack_pivot.db import connect
from attack_pivot.settings import options, secrets

router = APIRouter(prefix="/pivot/settings", tags=["pivot-settings"])


def require_admin(x_pivot_admin_token: str | None = Header(default=None)):
    expected = os.environ.get("PIVOT_ADMIN_TOKEN")
    if not expected:
        raise HTTPException(
            403, "settings are disabled: PIVOT_ADMIN_TOKEN is not configured"
        )
    if not x_pivot_admin_token or not hmac.compare_digest(
        x_pivot_admin_token.encode(), expected.encode()
    ):
        raise HTTPException(403, "invalid admin token")


def get_conn():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


class OptionValue(BaseModel):
    value: str | int


class SecretValue(BaseModel):
    value: str


@router.get("", dependencies=[Depends(require_admin)])
def read_settings(conn=Depends(get_conn)):
    return {"options": options.list_all(conn), "secrets": secrets.status(conn)}


@router.put("/options/{key}", dependencies=[Depends(require_admin)])
def put_option(key: str, body: OptionValue, conn=Depends(get_conn)):
    try:
        options.set_value(conn, key, body.value)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return {"options": options.list_all(conn)}


@router.delete("/options/{key}", dependencies=[Depends(require_admin)])
def delete_option(key: str, conn=Depends(get_conn)):
    try:
        options.reset(conn, key)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    return {"options": options.list_all(conn)}


@router.put("/secrets/{name}", dependencies=[Depends(require_admin)])
def put_secret(name: str, body: SecretValue, conn=Depends(get_conn)):
    try:
        secrets.set_secret(conn, name, body.value)
    except ValueError as e:
        raise HTTPException(422, str(e).replace(body.value, "[redacted]")) from None
    return {"secrets": secrets.status(conn)}


@router.delete("/secrets/{name}", dependencies=[Depends(require_admin)])
def delete_secret(name: str, conn=Depends(get_conn)):
    try:
        secrets.delete_secret(conn, name)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    return {"secrets": secrets.status(conn)}
