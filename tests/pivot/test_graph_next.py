import pytest

from attack_pivot.graph import sync as graph_sync
from attack_pivot.graph.age import cypher
from attack_pivot.model import build

pytestmark = pytest.mark.pivot_db


def _next_count(conn):
    return cypher(conn, "MATCH ()-[n:NEXT]->() RETURN count(n)")[0]["result"]


def test_no_next_edges_without_a_run(corpus_db):
    assert graph_sync.sync(corpus_db)["NEXT"] == 0
    assert _next_count(corpus_db) == 0


def test_active_run_is_materialized_by_default(corpus_db):
    run_id, summary = build.build_run(corpus_db, activate=True)
    counts = graph_sync.sync(corpus_db)
    assert counts["NEXT"] == summary["estimates"] == _next_count(corpus_db)
    rows = cypher(
        corpus_db,
        "MATCH (:Technique {attack_id:'T1566'})-[n:NEXT]->(b) WHERE n.level = 'technique' "
        "RETURN b.attack_id, n.p ORDER BY n.p DESC",
        columns=("dst", "p"),
    )
    assert rows and rows[0]["p"] >= rows[-1]["p"]
    top = cypher(
        corpus_db,
        "MATCH (:Technique {attack_id:'T1566'})-[n:NEXT]->(:Technique) WHERE n.level = 'technique' "
        "RETURN n.n_ab, n.n_a, n.ci_low, n.ci_high, n.run_id, n.p ORDER BY n.p DESC LIMIT 1",
        columns=("n_ab", "n_a", "lo", "hi", "run", "p"),
    )[0]
    assert top["run"] == str(run_id) and top["n_a"] > 0 and top["lo"] <= top["hi"]


def test_start_and_end_states_and_the_tactic_level(corpus_db):
    build.build_run(corpus_db, activate=True)
    graph_sync.sync(corpus_db)
    starts = cypher(
        corpus_db,
        "MATCH (:State {name:'START'})-[n:NEXT]->(t:Technique) WHERE n.level = 'technique' AND n.n_ab > 0 RETURN count(t)",
    )[0]["result"]
    ends = cypher(
        corpus_db,
        "MATCH (t:Technique)-[n:NEXT]->(:State {name:'END'}) WHERE n.level = 'technique' AND n.n_ab > 0 RETURN count(t)",
    )[0]["result"]
    tactic = cypher(
        corpus_db,
        "MATCH (:Tactic)-[n:NEXT]->(:Tactic) WHERE n.level = 'tactic' RETURN count(n)",
    )[0]["result"]
    assert starts > 0 and ends > 0 and tactic > 0


def test_explicit_run_replaces_the_previous_materialization(corpus_db):
    first = build.build_run(corpus_db, label="a", activate=True)[0]
    second = build.build_run(corpus_db, label="b", alpha=3.0)[0]
    graph_sync.sync(corpus_db)
    runs = {
        r["run"]
        for r in cypher(
            corpus_db,
            "MATCH ()-[n:NEXT]->() RETURN DISTINCT n.run_id",
            columns=("run",),
        )
    }
    assert runs == {str(first)}
    graph_sync.sync(corpus_db, run="b")
    runs = {
        r["run"]
        for r in cypher(
            corpus_db,
            "MATCH ()-[n:NEXT]->() RETURN DISTINCT n.run_id",
            columns=("run",),
        )
    }
    assert runs == {str(second)}
    with pytest.raises(RuntimeError, match="no model run"):
        graph_sync.sync(corpus_db, run="missing")
