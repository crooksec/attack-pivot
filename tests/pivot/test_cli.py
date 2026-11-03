import pytest

from attack_pivot.cli import build_parser, main
from attack_pivot.db.connection import AGE_SESSION_SQL, database_url


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "afp" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage: afp" in capsys.readouterr().out


def test_parser_builds():
    assert build_parser().prog == "afp"


def test_database_url_requires_setting(monkeypatch):
    monkeypatch.delenv("PIVOT_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        database_url()
    assert database_url("postgresql://x") == "postgresql://x"


def test_age_session_sql_loads_age_and_sets_search_path():
    assert "LOAD 'age'" in AGE_SESSION_SQL
    assert "ag_catalog" in AGE_SESSION_SQL


@pytest.mark.pivot_db
def test_connect_loads_age(pivot_url):
    from attack_pivot.db import connect

    with connect(pivot_url) as conn:
        names = [
            r["name"] for r in conn.execute("SELECT name FROM ag_graph").fetchall()
        ]
    assert "pivot_graph" in names
