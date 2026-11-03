import json
from pathlib import Path

import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.graph import sync as graph_sync
from attack_pivot.graph.age import cypher, parse_agtype
from attack_pivot.ingest import load
from attack_pivot.normalize import attack

ROOT = Path(__file__).resolve().parents[2]
MINI = json.loads((Path(__file__).parent / "fixtures" / "attack_mini.json").read_text())
FLOWS = [
    ROOT / "corpus" / n for n in ("Cobalt Kitty Campaign.afb", "Conti Ransomware.afb")
]

pytestmark = pytest.mark.pivot_db


@pytest.fixture
def seeded(scratch_db_url):
    """ATT&CK 20.0 (mini fixture + every ID the test flows use), two flows, one analytic."""
    from attack_pivot.ingest.afb import parse_afb_file

    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        attack.load(conn, attack.parse_bundle(MINI, "20.0"))
        for path in FLOWS:
            for a in parse_afb_file(path).actions:
                if a.technique_id:
                    conn.execute(
                        "INSERT INTO pivot.technique (attack_id, version, name) VALUES (%s, '20.0', %s) "
                        "ON CONFLICT DO NOTHING",
                        (a.technique_id, a.technique_id),
                    )
        actor = conn.execute(
            "SELECT id FROM pivot.actor WHERE attack_group_id = 'G0016'"
        ).fetchone()["id"]
        conn.execute(
            "INSERT INTO pivot.actor_alias (actor_id, alias) VALUES (%s, 'OceanLotus')",
            (actor,),
        )
        conn.commit()
        load.ingest_paths(conn, FLOWS, version="20.0")
        conn.execute(
            "INSERT INTO pivot.analytic (id, title, information_domain) VALUES ('CAR-2020-09-001', 'PS', 'Host')"
        )
        conn.execute(
            "INSERT INTO pivot.analytic_technique (analytic_id, technique_id, coverage) "
            "VALUES ('CAR-2020-09-001', 'T1059.001', 'Moderate')"
        )
        flow = conn.execute(
            "SELECT id FROM pivot.flow WHERE name = 'Conti Ransomware'"
        ).fetchone()["id"]
        conn.execute(
            "INSERT INTO pivot.veris_incident (id, victim_industry, year, flow_id) VALUES ('V1', '52', 2022, %s)",
            (flow,),
        )
        conn.commit()
        yield conn


def _n(conn, query):
    return cypher(conn, query)[0]["result"]


def test_acceptance_queries(seeded):
    graph_sync.sync(seeded)
    subs = _n(
        seeded,
        "MATCH (t:Technique {attack_id:'T1059'})<-[:SUBTECHNIQUE_OF]-(s) RETURN count(s)",
    )
    assert subs > 0
    assert (
        _n(seeded, "MATCH (:Technique)-[d:DETECTABLE_BY]->(:Analytic) RETURN count(d)")
        == 1
    )
    row = cypher(
        seeded,
        "MATCH (t:Technique {attack_id:'T1059.001'})-[d:DETECTABLE_BY]->(a:Analytic) RETURN a.id, d.coverage",
        columns=("id", "coverage"),
    )
    assert row == [{"id": "CAR-2020-09-001", "coverage": "Moderate"}]


def test_vertices_and_edges(seeded):
    counts = graph_sync.sync(seeded)
    assert counts["Flow"] == counts["Incident"] == counts["Report"] == 2
    assert (
        counts["Source"] == 3 and counts["State"] == 2 and counts["Tactic"] == 2
    )  # upstream + manual
    assert counts["PART_OF"] == counts["REPORTED_IN"] == counts["PUBLISHED_BY"] == 2
    assert counts["CODED_AS"] == 1
    # Cobalt Kitty: the OceanLotus alias resolves to G0016 at ingest
    assert counts["ATTRIBUTED_TO"] == 1
    in_tactic = _n(
        seeded,
        "MATCH (:Technique {attack_id:'T1059.001'})-[e:IN_TACTIC]->(:Tactic {attack_id:'TA0002'}) RETURN count(e)",
    )
    assert in_tactic == 1
    assert (
        _n(seeded, "MATCH (t:Technique) WHERE t.attack_id = 'T1086' RETURN count(t)")
        == 0
    )  # revoked is skipped
    observed = cypher(
        seeded,
        "MATCH (f:Flow {name:'Conti Ransomware'})-[o:OBSERVED]->(t:Technique) RETURN t.attack_id, o.`count`",
        columns=("technique", "count"),
    )
    assert observed and all(r["count"] >= 1 for r in observed)


def test_attribution_edge_uses_best_confidence(seeded):
    actor = seeded.execute(
        "SELECT id FROM pivot.actor WHERE attack_group_id = 'G0016'"
    ).fetchone()["id"]
    flow = seeded.execute(
        "SELECT id FROM pivot.flow WHERE name = 'Conti Ransomware'"
    ).fetchone()["id"]
    seeded.execute(
        "INSERT INTO pivot.flow_actor (flow_id, actor_id, attribution_confidence, basis) VALUES (%s, %s, 0.5, 'test')",
        (flow, actor),
    )
    seeded.commit()
    assert graph_sync.sync(seeded)["ATTRIBUTED_TO"] == 2
    rows = cypher(
        seeded,
        "MATCH (i:Incident)-[a:ATTRIBUTED_TO]->(g:Group) RETURN i.label, g.attack_group_id, a.confidence",
        columns=("incident", "g", "c"),
    )
    assert {(r["incident"], r["g"], r["c"]) for r in rows} == {
        ("Cobalt Kitty Campaign", "G0016", 1.0),
        ("Conti Ransomware", "G0016", 0.5),
    }


def test_sync_is_rebuildable_and_leaves_relational_data_alone(seeded):
    tables = ("flow", "action_obs", "transition_obs", "technique", "analytic")
    before = {
        t: seeded.execute(f"SELECT count(*) AS n FROM pivot.{t}").fetchone()["n"]
        for t in tables
    }
    first = graph_sync.sync(seeded)
    second = graph_sync.sync(seeded)
    assert first == second
    assert _n(seeded, "MATCH (n) RETURN count(n)") == sum(
        first[l] for l in graph_sync.VERTEX_LABELS
    )
    assert _n(seeded, "MATCH ()-[e]->() RETURN count(e)") == sum(
        first[l] for l in graph_sync.EDGE_LABELS
    )
    after = {
        t: seeded.execute(f"SELECT count(*) AS n FROM pivot.{t}").fetchone()["n"]
        for t in tables
    }
    assert before == after


def test_requires_attack_version(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        with pytest.raises(RuntimeError, match="afp attack sync"):
            graph_sync.sync(conn)


def test_cli_graph_sync(seeded, scratch_db_url, capsys):
    assert main(["--database-url", scratch_db_url, "graph", "sync"]) == 0
    assert "graph synced:" in capsys.readouterr().out


def test_parse_agtype():
    assert (
        parse_agtype('{"id": 1, "label": "T", "properties": {"a": 1}}::vertex')["label"]
        == "T"
    )
    assert parse_agtype("3") == 3
    assert parse_agtype(None) is None
