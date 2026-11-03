import pytest

from attack_pivot.cli import main
from attack_pivot.model import build

pytestmark = pytest.mark.pivot_db


def test_build_persists_a_run_with_n_and_interval_on_every_row(corpus_db):
    run_id, summary = build.build_run(corpus_db, label="t")
    run = corpus_db.execute(
        "SELECT * FROM pivot.model_run WHERE id = %s", (run_id,)
    ).fetchone()
    assert (
        run["label"] == "t" and run["attack_version"] == "test" and not run["is_active"]
    )
    assert run["params"]["level"] == "technique" and run["params"]["stored_levels"] == [
        "technique",
        "tactic",
    ]
    assert run["corpus_stats"]["incidents"] == 38
    assert run["corpus_stats"]["by_source_class"] == {"independent": 36, "emulation": 2}
    assert run["corpus_stats"]["by_tlp"] == {"clear": 38}
    assert run["corpus_stats"]["edges_by_order_basis"].get("explicit")
    rows = corpus_db.execute(
        "SELECT * FROM pivot.transition_estimate WHERE run_id = %s", (run_id,)
    ).fetchall()
    assert len(rows) == summary["estimates"] > 0
    assert {r["level"] for r in rows} == {"technique", "tactic"}
    for r in rows:
        assert r["n_a"] > 0 and 0 < r["p"] < 1
        assert 0 <= r["ci_low"] <= r["ci_high"] <= 1
        if r["n_ab"] > 0:  # observed: the mean is inside the interval
            assert r["ci_low"] <= r["p"] <= r["ci_high"]
        # prior-only cells (n_ab == 0) are so right-skewed (Beta shape << 1) that the mean can
        # lie above the 95th percentile; the quantiles are stored as the SPEC defines them.
        assert r["p_mle"] == pytest.approx(r["n_ab"] / r["n_a"])
    top = corpus_db.execute(
        "SELECT dst, n_ab FROM pivot.transition_estimate WHERE run_id = %s AND level = 'technique' AND src = 'START' "
        "ORDER BY p DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    assert top["n_ab"] > 0


def test_prior_only_successors_are_capped_per_source(corpus_db):
    run_id, _ = build.build_run(corpus_db, top_prior=3)
    worst = corpus_db.execute(
        "SELECT max(n) AS n FROM (SELECT count(*) AS n FROM pivot.transition_estimate "
        "WHERE run_id = %s AND n_ab = 0 GROUP BY level, src) x",
        (run_id,),
    ).fetchone()["n"]
    assert worst == 3


def test_same_inputs_give_identical_hash(corpus_db):
    a = build.build_run(corpus_db)[1]["sha256"]
    b = build.build_run(corpus_db)[1]["sha256"]
    c = build.build_run(corpus_db, alpha=2.0)[1]["sha256"]
    assert a == b != c


def test_filters_change_the_corpus_and_are_recorded(corpus_db):
    run_id, summary = build.build_run(
        corpus_db, corpus_filter={"source_class": ["emulation"]}
    )
    assert summary["corpus"]["incidents"] == 2
    stored = corpus_db.execute(
        "SELECT corpus_filter FROM pivot.model_run WHERE id = %s", (run_id,)
    ).fetchone()
    assert stored["corpus_filter"] == {"source_class": ["emulation"]}
    with pytest.raises(RuntimeError, match="no incidents"):
        build.build_run(corpus_db, corpus_filter={"tlp": ["red"]})


def test_order_basis_filter_removes_everything_when_nothing_matches(corpus_db):
    with pytest.raises(RuntimeError, match="no incidents"):
        build.build_run(corpus_db, bases=("inferred_llm",))


def test_activate_keeps_a_single_active_run(corpus_db):
    first = build.build_run(corpus_db, activate=True)[0]
    second = build.build_run(corpus_db, label="second")[0]
    assert build.resolve_run(corpus_db, "active") == first
    build.activate(corpus_db, second)
    assert build.resolve_run(corpus_db, "active") == second
    assert (
        corpus_db.execute(
            "SELECT count(*) AS n FROM pivot.model_run WHERE is_active"
        ).fetchone()["n"]
        == 1
    )
    assert build.resolve_run(corpus_db, "second") == second
    assert build.resolve_run(corpus_db, str(first)[:8]) == first
    with pytest.raises(RuntimeError, match="no model run"):
        build.resolve_run(corpus_db, "nope")
    with pytest.raises(RuntimeError, match="no model run"):
        build.activate(corpus_db, "00000000-0000-0000-0000-000000000000")


def test_all_levels(corpus_db):
    run_id, _ = build.build_run(corpus_db, level="subtechnique")
    levels = corpus_db.execute(
        "SELECT DISTINCT level FROM pivot.transition_estimate WHERE run_id = %s",
        (run_id,),
    ).fetchall()
    assert {r["level"] for r in levels} == {"subtechnique", "technique", "tactic"}
    tactic = corpus_db.execute(
        "SELECT n_ab FROM pivot.transition_estimate WHERE run_id = %s AND level = 'tactic' AND n_ab <> round(n_ab::numeric)",
        (run_id,),
    ).fetchall()
    assert tactic  # fractional counts exist at tactic level (multi-tactic techniques)


def test_cli_build_list_activate(corpus_db, capsys):
    url = corpus_db.info.dsn  # noqa: F841 (documented: CLI uses --database-url)
    import psycopg.conninfo as ci

    dsn = ci.make_conninfo(corpus_db.info.dsn, password=corpus_db.info.password)
    assert (
        main(["--database-url", dsn, "model", "build", "--label", "cli", "--activate"])
        == 0
    )
    out = capsys.readouterr().out
    assert "(active)" in out and "38 incidents" in out
    assert main(["--database-url", dsn, "model", "list"]) == 0
    assert "cli" in capsys.readouterr().out
    assert main(["--database-url", dsn, "model", "activate", "cli"]) == 0
