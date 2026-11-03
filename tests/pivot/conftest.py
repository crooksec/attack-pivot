import os

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "pivot_db: needs a running pivot-db (PIVOT_DATABASE_URL)"
    )


@pytest.fixture
def pivot_url():
    url = os.environ.get("PIVOT_DATABASE_URL")
    if not url:
        pytest.skip("PIVOT_DATABASE_URL not set")
    return url


@pytest.fixture
def scratch_db_url(pivot_url):
    """A throwaway database on the pivot server, dropped after the test."""
    import uuid

    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    name = f"pivot_test_{uuid.uuid4().hex[:10]}"
    admin = psycopg.connect(
        make_conninfo(pivot_url, dbname="postgres"), autocommit=True
    )
    admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield make_conninfo(
            pivot_url, **{**conninfo_to_dict(pivot_url), "dbname": name}
        )
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
