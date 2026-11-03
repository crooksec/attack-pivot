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
