from datetime import date, timedelta

import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.dedupe import run
from attack_pivot.dedupe import score as s

D = date(2026, 3, 1)
T = {"T1566", "T1204", "T1059", "T1003"}


def f(id, first=D, last=None, actors=(), techniques=T, tags=(), urls=()):
    last = last or first
    return s.Features(
        id, first, last, set(actors), set(techniques), set(tags), set(urls)
    )


def test_same_actor_same_week_same_techniques_scores_one():
    score, signals = s.score_pair(
        f("a", actors={"g1"}), f("b", D + timedelta(days=0), actors={"g1"})
    )
    assert score == 1.0 and signals["actor"] == "shared" and signals["jaccard"] == 1.0


def test_both_unknown_actors_is_a_weak_actor_signal():
    score, signals = s.score_pair(f("a"), f("b"))
    assert (
        score == pytest.approx(0.25 * 0.3 + 0.2 + 0.55)
        and signals["actor"] == "both_unknown"
    )
    assert score >= s.AUTO_LINK


@pytest.mark.parametrize(
    "a, b",
    [
        (f("a", actors={"g1"}), f("b", actors={"g2"})),  # different actors
        (f("a", actors={"g1"}), f("b")),  # one known, one unknown
        (f("a"), f("b", D + timedelta(days=60))),  # outside the 45-day window
        (f("a", techniques={"T1"}), f("b", techniques={"T2"})),  # nothing in common
        (
            f("a", techniques={"T1", "T2", "T3"}),
            f("b", techniques={"T1", "T4", "T5"}),
        ),  # jaccard 0.2
    ],
)
def test_not_candidates(a, b):
    assert s.score_pair(a, b) is None


def test_date_windows_use_interval_gap():
    a = f("a", D, D + timedelta(days=10))
    inside = f("b", D + timedelta(days=40))  # 30 days after a's last_seen
    outside = f("c", D + timedelta(days=60))  # 50 days after
    assert s.score_pair(a, inside)[1]["gap_days"] == 30
    assert s.score_pair(a, outside) is None
    overlapping = f("d", D + timedelta(days=5), D + timedelta(days=20))
    assert s.score_pair(a, overlapping)[1]["gap_days"] == 0


def test_date_decay_moves_a_pair_between_bands():
    close = s.score_pair(f("a"), f("b", D))[0]
    far = s.score_pair(f("a"), f("b", D + timedelta(days=44)))[0]
    assert close >= s.AUTO_LINK > far >= s.REVIEW


def test_sector_or_url_alone_can_be_a_candidate_but_sector_never_auto_links():
    other = {"T7", "T8", "T9"}
    sector = s.score_pair(
        f("a", techniques={"T1"}, tags={"finance"}),
        f("b", techniques=other, tags={"finance"}),
    )
    assert sector[0] < s.AUTO_LINK and sector[1]["shared_tags"] == ["finance"]
    url = s.score_pair(
        f("a", actors={"g"}, techniques={"T1"}, urls={"https://x.example/r"}),
        f("b", actors={"g"}, techniques=other, urls={"https://x.example/r"}),
    )
    assert url[0] >= s.AUTO_LINK  # same actor, same week, shared citation


def test_undated_incidents_never_reach_auto_link():
    undated = s.Features("u", None, None, set(), set(T), set(), set())
    score, signals = s.score_pair(undated, f("b"))
    assert score == pytest.approx(0.25 * 0.3 + 0.55)
    assert score < s.AUTO_LINK and signals["gap_days"] is None
    # even with everything else maxed out, the cap holds
    strong = s.Features("v", None, None, {"g"}, set(T), set(), {"https://x.example"})
    other = s.Features("w", None, None, {"g"}, set(T), set(), {"https://x.example"})
    assert s.score_pair(strong, other)[0] == s.UNDATED_CAP


def test_candidates_apply_the_review_floor():
    pairs = s.candidates([f("a"), f("b"), f("c", D + timedelta(days=200))])
    assert [(a, b) for a, b, *_ in pairs] == [("a", "b")]


def test_urls_in():
    value = [
        [
            "id",
            [
                ["url", "https://a.example/x"],
                ["description", "see (https://b.example/y)."],
            ],
        ]
    ]
    assert s.urls_in(value) == {"https://a.example/x", "https://b.example/y"}


def test_components_are_transitive_and_report_the_weakest_link():
    comps = run._components(
        [("a", "b", 0.9, {}), ("b", "c", 0.8, {}), ("x", "y", 0.76, {})]
    )
    assert sorted(comps) == [(["a", "b", "c"], 0.8), (["x", "y"], 0.76)]


# -- database ---------------------------------------------------------------------------------


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        yield conn


def add_flow(conn, label, first, techniques=T, actor=None, tags=(), url=None):
    """A flow with its own singleton incident (as ingest creates them)."""
    inc = conn.execute(
        "INSERT INTO pivot.incident (label, first_seen, last_seen, cluster_method, cluster_confidence) "
        "VALUES (%s, %s, %s, 'singleton', 1.0) RETURNING id",
        (label, first, first),
    ).fetchone()["id"]
    report = conn.execute(
        "INSERT INTO pivot.report (url, title, tlp, triage_status) VALUES (%s, %s, 'clear', 'extracted') RETURNING id",
        (url, label),
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO pivot.report_incident (report_id, incident_id, link_confidence, method) VALUES (%s, %s, 1.0, 'singleton')",
        (report, inc),
    )
    flow = conn.execute(
        "INSERT INTO pivot.flow (report_id, incident_id, name, origin) VALUES (%s, %s, %s, 'llm') RETURNING id",
        (report, inc, label),
    ).fetchone()["id"]
    prev = None
    for i, t in enumerate(sorted(techniques)):
        a = conn.execute(
            "INSERT INTO pivot.action_obs (flow_id, node_ref, technique_id) VALUES (%s, %s, %s) RETURNING id",
            (flow, f"n{i}", t),
        ).fetchone()["id"]
        if prev:
            conn.execute(
                "INSERT INTO pivot.transition_obs (flow_id, incident_id, src_action, dst_action, order_basis) VALUES (%s, %s, %s, %s, 'explicit')",
                (flow, inc, prev, a),
            )
        prev = a
    if actor:
        row = conn.execute(
            "SELECT id FROM pivot.actor WHERE name = %s", (actor,)
        ).fetchone()
        aid = (
            row["id"]
            if row
            else conn.execute(
                "INSERT INTO pivot.actor (name) VALUES (%s) RETURNING id", (actor,)
            ).fetchone()["id"]
        )
        conn.execute(
            "INSERT INTO pivot.flow_actor (flow_id, actor_id, attribution_confidence) VALUES (%s, %s, 1.0)",
            (flow, aid),
        )
    if tags:
        conn.execute(
            "INSERT INTO pivot.flow_context (flow_id, sectors) VALUES (%s, %s)",
            (flow, list(tags)),
        )
    conn.commit()
    return inc, flow


def incidents(conn):
    return conn.execute("SELECT count(*) AS n FROM pivot.incident").fetchone()["n"]


@pytest.mark.pivot_db
def test_auto_link_merges_flows_and_keeps_the_one_incident_invariant(db):
    a, fa = add_flow(db, "A", D, actor="APT1")
    b, fb = add_flow(db, "B", D + timedelta(days=3), actor="APT1")
    c, fc = add_flow(
        db, "C", D + timedelta(days=1), actor="APT2"
    )  # different actor: stays apart
    counts = run.dedupe(db)
    assert (
        counts["incidents_before"],
        counts["auto_linked"],
        counts["incidents_after"],
    ) == (3, 1, 2)
    inc = {
        r["name"]: r["incident_id"]
        for r in db.execute("SELECT name, incident_id FROM pivot.flow")
    }
    assert inc["A"] == inc["B"] != inc["C"]
    keep = db.execute(
        "SELECT * FROM pivot.incident WHERE id = %s", (inc["A"],)
    ).fetchone()
    assert (
        keep["cluster_method"] == "dedupe:auto"
        and keep["first_seen"] == D
        and keep["last_seen"] == D + timedelta(days=3)
    )
    # transitions moved with their flows; both reports are linked to the surviving incident
    assert (
        db.execute(
            "SELECT count(DISTINCT incident_id) AS n FROM pivot.transition_obs WHERE flow_id IN (%s, %s)",
            (fa, fb),
        ).fetchone()["n"]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) AS n FROM pivot.report_incident WHERE incident_id = %s",
            (inc["A"],),
        ).fetchone()["n"]
        == 2
    )
    # every flow has exactly one existing incident
    assert (
        db.execute(
            "SELECT count(*) AS n FROM pivot.flow f LEFT JOIN pivot.incident i ON i.id = f.incident_id WHERE i.id IS NULL"
        ).fetchone()["n"]
        == 0
    )
    assert run.dedupe(db)["auto_linked"] == 0  # idempotent


@pytest.mark.pivot_db
def test_review_queue_merge_and_distinct(db):
    add_flow(db, "A", D)
    add_flow(db, "B", D + timedelta(days=44))  # weak date score -> review band
    add_flow(
        db, "C", D + timedelta(days=1), techniques={"T9", "T8", "T7"}, tags=("finance",)
    )
    add_flow(
        db, "D", D + timedelta(days=2), techniques={"T6", "T5", "T4"}, tags=("finance",)
    )
    counts = run.dedupe(db)
    assert counts["auto_linked"] == 0 and counts["queued"] == 2 and incidents(db) == 4
    items = run.queue(db)
    assert [round(i["score"], 2) for i in items] == sorted(
        (round(i["score"], 2) for i in items), reverse=True
    )
    pair = {frozenset((i["label_a"], i["label_b"])): i["id"] for i in items}
    run.resolve(db, pair[frozenset("AB")], merge=True, by="pcrook")
    assert incidents(db) == 3
    assert (
        db.execute(
            "SELECT cluster_method FROM pivot.incident WHERE label IN ('A', 'B')"
        ).fetchone()["cluster_method"]
        == "dedupe:review"
    )
    run.resolve(db, pair[frozenset("CD")], merge=False, by="pcrook")
    assert run.queue(db) == []
    again = run.dedupe(db)  # a distinct pair is never proposed again
    assert again["queued"] == 0 and incidents(db) == 3
    with pytest.raises(RuntimeError, match="no open review item"):
        run.resolve(db, pair[frozenset("CD")], merge=True, by="x")


@pytest.mark.pivot_db
def test_distinct_decision_blocks_an_auto_link(db):
    add_flow(db, "A", D, actor="APT1")
    add_flow(db, "B", D, actor="APT1")
    a, b = [r["id"] for r in db.execute("SELECT id FROM pivot.incident ORDER BY id")]
    db.execute(
        "INSERT INTO pivot.dedupe_candidate (incident_a, incident_b, score, signals, status) VALUES (%s, %s, 1.0, '{}'::jsonb, 'distinct')",
        (min(a, b), max(a, b)),
    )
    db.commit()
    assert run.dedupe(db)["auto_linked"] == 0 and incidents(db) == 2


@pytest.mark.pivot_db
def test_auto_only_does_not_fill_the_queue_and_urls_link_flows(db):
    add_flow(db, "A", D, actor="G", techniques={"T1"}, url="https://x.example/a")
    add_flow(db, "B", D, actor="G", techniques={"T2"}, url="https://x.example/b")
    db.execute(
        "UPDATE pivot.flow SET afb = jsonb_build_object('objects', jsonb_build_array(jsonb_build_object('id', 'flow', 'properties', jsonb_build_array(jsonb_build_array('external_references', 'cites https://x.example/a')))))"
        " WHERE name = 'B'"
    )
    db.commit()
    feats = run.load_features(db)
    urls = {f.id: f.urls for f in feats.values()}
    assert any(
        "https://x.example/a" in u and "https://x.example/b" in u for u in urls.values()
    )
    counts = run.dedupe(db, auto_only=True)
    assert counts["auto_linked"] == 1 and counts["queued"] == 0


@pytest.mark.pivot_db
def test_cli_dedupe(scratch_db_url, capsys):
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    assert main([*url, "dedupe"]) == 0
    assert "incidents_before=0" in capsys.readouterr().out
    assert main([*url, "dedupe", "queue"]) == 0
    assert "0 open" in capsys.readouterr().out
    assert main([*url, "dedupe", "resolve", "nope", "--merge", "--by", "me"]) == 1
