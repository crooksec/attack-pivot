import pytest

from attack_pivot.cli import main
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.review import queue

pytestmark = pytest.mark.pivot_db


@pytest.fixture
def db(scratch_db_url):
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        for name, cls in (("Gov", "government"), ("Vend", "vendor")):
            conn.execute(
                "INSERT INTO pivot.source (name, source_class) VALUES (%s, %s)",
                (name, cls),
            )
        conn.commit()
        yield conn


def add_flow(
    conn,
    name,
    source="Vend",
    techniques=("T1", "T2", "T3"),
    basis="inferred_llm",
    origin="llm",
):
    """A linear flow a0 -> a1 -> a2 ..."""
    src = conn.execute(
        "SELECT id FROM pivot.source WHERE name = %s", (source,)
    ).fetchone()["id"]
    inc = conn.execute(
        "INSERT INTO pivot.incident (label) VALUES (%s) RETURNING id", (name,)
    ).fetchone()["id"]
    rep = conn.execute(
        "INSERT INTO pivot.report (source_id, url, title, tlp) VALUES (%s, %s, %s, 'clear') RETURNING id",
        (src, f"https://x.example/{name}", name),
    ).fetchone()["id"]
    flow = conn.execute(
        "INSERT INTO pivot.flow (report_id, incident_id, name, origin) VALUES (%s, %s, %s, %s) RETURNING id",
        (rep, inc, name, origin),
    ).fetchone()["id"]
    acts = [
        conn.execute(
            "INSERT INTO pivot.action_obs (flow_id, node_ref, technique_id, name) VALUES (%s, %s, %s, %s) RETURNING id",
            (flow, f"a{i}", t, f"{name}-{i}"),
        ).fetchone()["id"]
        for i, t in enumerate(techniques)
    ]
    for i in range(len(acts) - 1):
        conn.execute(
            "INSERT INTO pivot.transition_obs (flow_id, incident_id, src_action, dst_action, src_technique, dst_technique, order_basis, via, delta_seconds) VALUES (%s, %s, %s, %s, %s, %s, %s, 'direct', 60)",
            (flow, inc, acts[i], acts[i + 1], techniques[i], techniques[i + 1], basis),
        )
    conn.commit()
    return str(flow)


def edges(conn, flow):
    return conn.execute(
        "SELECT id::text, src_technique AS s, dst_technique AS d, order_basis AS b, delta_seconds FROM pivot.transition_obs WHERE flow_id::text = %s ORDER BY src_technique, dst_technique",
        (flow,),
    ).fetchall()


def verdicts(conn, flow):
    return sorted(
        r["verdict"]
        for r in conn.execute(
            "SELECT verdict FROM pivot.review_edge WHERE flow_id::text = %s", (flow,)
        )
    )


def test_sample_is_stratified_seeded_and_never_repeats(db):
    gov = [add_flow(db, f"g{i}", "Gov") for i in range(6)]
    vend = [add_flow(db, f"v{i}", "Vend") for i in range(14)]
    add_flow(db, "seed", "Gov", origin="upstream_corpus")  # not LLM: never sampled
    first = queue.sample(db, "b1", fraction=0.25, cap=50, seed=3)
    assert len(first) == 5  # ceil(0.25 * 20)
    classes = {r["id"]: r["source_class"] for r in queue.pending(db, "b1")}
    assert (
        sorted(classes.values()).count("government") >= 1
        and "vendor" in classes.values()
    )
    assert set(first) <= set(gov + vend)
    again = queue.sample(db, "b2", fraction=0.25, cap=2, seed=3)
    assert len(again) == 2 and not set(again) & set(first)  # cap respected, no overlap
    with pytest.raises(RuntimeError, match="already exists"):
        queue.sample(db, "b1")
    assert (
        queue.sample(db, "empty", fraction=0.0001) != []
    )  # at least one when anything is eligible


def test_sample_is_reproducible(db):
    for i in range(10):
        add_flow(db, f"f{i}")
    a = queue.sample(db, "x", fraction=0.3, seed=7)
    db.execute("UPDATE pivot.flow SET review_batch = NULL")
    db.commit()
    assert queue.sample(db, "y", fraction=0.3, seed=7) == a


def test_accept_logs_every_edge_correct(db):
    flow = add_flow(db, "f")
    queue.accept(db, flow, "pcrook")
    assert verdicts(db, flow) == ["correct", "correct"]
    row = db.execute(
        "SELECT review_status, reviewer, reviewed_at IS NOT NULL AS stamped FROM pivot.flow"
    ).fetchone()
    assert row == {"review_status": "accepted", "reviewer": "pcrook", "stamped": True}
    with pytest.raises(RuntimeError, match="already accepted"):
        queue.accept(db, flow, "pcrook")


def test_correct_flip_basis_delete_add(db):
    flow = add_flow(db, "f", techniques=("T1", "T2", "T3", "T4"))
    e = {(r["s"], r["d"]): r["id"][:8] for r in edges(db, flow)}
    queue.correct(
        db, flow, "pcrook",
        flip=[e[("T1", "T2")]], delete=[e[("T3", "T4")]],
        basis={e[("T2", "T3")]: "explicit"}, add=[("a0", "a3", "inferred_narrative")],
    )  # fmt: skip
    got = {(r["s"], r["d"]): (r["b"], r["delta_seconds"]) for r in edges(db, flow)}
    assert got == {
        ("T2", "T1"): ("inferred_llm", -60),  # flipped, delta negated
        ("T2", "T3"): ("explicit", 60),
        ("T1", "T4"): ("inferred_narrative", None),
    }
    assert verdicts(db, flow) == sorted(
        ["flipped", "basis_changed", "spurious", "missed"]
    )
    assert (
        db.execute("SELECT review_status FROM pivot.flow").fetchone()["review_status"]
        == "corrected"
    )


def test_untouched_edges_are_correct_and_added_edges_are_not_double_counted(db):
    flow = add_flow(db, "f")
    queue.correct(db, flow, "me", add=[("a0", "a2", "explicit")])
    assert verdicts(db, flow) == ["correct", "correct", "missed"]


def test_flip_and_basis_on_one_edge(db):
    flow = add_flow(db, "f")
    e = edges(db, flow)[0]["id"][:8]
    queue.correct(db, flow, "me", flip=[e], basis={e: "timestamp"})
    assert "flipped_and_basis_changed" in verdicts(db, flow)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"basis": {"zzzz": "explicit"}}, "not one edge"),
        ({"add": [("a0", "nope", "explicit")]}, "no action"),
        ({"add": [("a0", "a1", "guessed")]}, "unknown order_basis"),
    ],
)
def test_correct_rejects_bad_input_without_partial_writes(db, kwargs, message):
    flow = add_flow(db, "f")
    with pytest.raises(RuntimeError, match=message):
        queue.correct(db, flow, "me", **kwargs)
    db.rollback()
    assert (
        db.execute("SELECT review_status FROM pivot.flow").fetchone()["review_status"]
        == "unreviewed"
    )
    assert (
        db.execute("SELECT count(*) AS n FROM pivot.review_edge").fetchone()["n"] == 0
    )


def test_delete_and_edit_of_one_edge_is_refused(db):
    flow = add_flow(db, "f")
    e = edges(db, flow)[0]["id"][:8]
    with pytest.raises(RuntimeError, match="both deleted and edited"):
        queue.correct(db, flow, "me", flip=[e], delete=[e])


def test_reject_counts_every_edge_wrong(db):
    flow = add_flow(db, "f")
    queue.reject(db, flow, "me")
    assert verdicts(db, flow) == ["spurious", "spurious"]
    assert (
        db.execute("SELECT review_status FROM pivot.flow").fetchone()["review_status"]
        == "rejected"
    )


def test_report_computes_prd_precision(db):
    for i in range(8):
        queue.accept(db, add_flow(db, f"ok{i}", "Gov"), "me")  # 16 correct edges
    bad = add_flow(db, "bad", "Vend", techniques=("T1", "T2", "T3", "T4"))  # 3 edges
    e = {(r["s"], r["d"]): r["id"][:8] for r in edges(db, bad)}
    queue.correct(
        db,
        bad,
        "me",
        flip=[e[("T1", "T2")]],
        basis={e[("T2", "T3")]: "explicit"},
        delete=[e[("T3", "T4")]],
    )
    r = queue.report(db)
    assert r["edges"] == 19 and r["both_correct"] == pytest.approx(16 / 19)
    assert r["direction_correct"] == pytest.approx(17 / 19)  # + the basis-only fix
    assert r["basis_correct"] == pytest.approx(17 / 19)  # + the flip-only fix
    assert (
        r["spurious"] == 1 and not r["passes"]
    )  # 0.84 < 0.85, and 9 of 9 reviewed < 50
    assert r["by_source_class"]["government"]["both_correct"] == 1.0
    assert r["by_source_class"]["vendor"]["both_correct"] == 0.0
    assert r["reviewed_flows_needed"] == 50 and r["reviewed_flows"] == 9


def test_report_passes_only_with_enough_reviewed_flows(db):
    flows = [add_flow(db, f"f{i}") for i in range(60)]
    for f in flows[:49]:
        queue.accept(db, f, "me")
    assert not queue.report(db)["passes"]  # precision 1.0 but 49 < 50 flows
    queue.accept(db, flows[49], "me")
    assert queue.report(db)["passes"]
    assert queue.report(db, batch="nope")["edges"] == 0


def test_cli_review(scratch_db_url, capsys):
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    with connect(scratch_db_url) as conn:
        conn.execute(
            "INSERT INTO pivot.source (name, source_class) VALUES ('V', 'vendor')"
        )
        conn.commit()
        flow = add_flow(conn, "f", "V")
    assert main([*url, "review", "sample", "--batch", "b", "--fraction", "1"]) == 0
    assert "1 flows" in capsys.readouterr().out
    assert main([*url, "review", "list", "--batch", "b"]) == 0
    assert "1 waiting" in capsys.readouterr().out
    assert main([*url, "review", "show", flow]) == 0
    out = capsys.readouterr().out
    assert "T1 -> T2" in out and "inferred_llm/direct" in out
    assert main([*url, "review", "correct", flow, "--by", "me", "--add", "bad"]) == 1
    assert main([*url, "review", "accept", flow, "--by", "me"]) == 0
    assert (
        main([*url, "review", "report", "--batch", "b"]) == 2
    )  # 1 flow reviewed of 50 needed


def test_rejected_and_corrected_flows_change_what_the_model_counts(corpus_db):
    from attack_pivot.model import counting
    from attack_pivot.model.counting import Params
    from attack_pivot.model.taxonomy import Taxonomy

    conn = corpus_db
    tax = Taxonomy.load(conn, "test")
    before = counting.count(counting.load_incidents(conn, Params(), tax))
    flow = conn.execute(
        "SELECT f.id::text AS id FROM pivot.flow f WHERE f.name = 'Conti Ransomware'"
    ).fetchone()["id"]
    conn.execute(
        "UPDATE pivot.flow SET origin = 'llm', review_status = 'unreviewed' WHERE id::text = %s",
        (flow,),
    )
    conn.commit()
    queue.reject(conn, flow, "me")
    after = counting.count(counting.load_incidents(conn, Params(), tax))
    assert after.incidents == before.incidents - 1
    assert sum(after.n_ab.values()) < sum(before.n_ab.values())
