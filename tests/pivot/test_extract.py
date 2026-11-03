import json

import httpx
import pytest

from attack_pivot.cli import main
from attack_pivot.collect import store
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.extract import api, run
from tests.pivot.test_order_basis import QUOTE, action, exported_afb


class FakeApi:
    """The API's job endpoints. ``fail`` maps a report title to a failure mode."""

    def __init__(self, afb, fail=None, polls=1):
        self.afb, self.fail, self.polls = afb, fail or {}, polls
        self.jobs, self.requests = {}, []

    def __call__(self, request):
        path = request.url.path.removeprefix("/api/v1")
        self.requests.append((request.method, path))
        if request.method == "POST" and path == "/jobs":
            body = json.loads(request.content)
            job_id = f"job-{len(self.jobs) + 1}"
            self.jobs[job_id] = {"body": body, "polled": 0}
            return httpx.Response(202, json={"job_id": job_id, "status": "queued"})
        job_id = path.split("/")[2]
        job = self.jobs[job_id]
        mode = self.fail.get(job["body"]["metadata"]["title"])
        if path.endswith("/artifacts/afb"):
            return httpx.Response(200, content=json.dumps(self.afb).encode())
        if path.endswith("/audit"):
            return httpx.Response(
                200,
                json={
                    "job_id": job_id,
                    "events": [
                        {
                            "event_type": "provider_invocation_completed",
                            "details": {"provider_id": "prov", "model_used": "mod-1"},
                        }
                    ],
                    "timestamps": {
                        "created_at": "2026-02-03T10:00:00Z",
                        "completed_at": "2026-02-03T10:00:12Z",
                    },
                },
            )
        job["polled"] += 1
        if job["polled"] <= self.polls:
            return httpx.Response(200, json={"status": "running", "artifacts": {}})
        if mode == "fail":
            return httpx.Response(
                200,
                json={
                    "status": "failed",
                    "error_code": "extraction_output_malformed",
                    "error_message": "bad json",
                    "artifacts": {},
                },
            )
        return httpx.Response(
            200,
            json={"status": "completed", "artifacts": {"has_afb": mode != "no-afb"}},
        )


def client(fake):
    return api.ApiClient(
        "http://api.test/api/v1",
        transport=httpx.MockTransport(fake),
        sleep=lambda s: None,
    )


AFB, _ = exported_afb(
    action(
        1,
        ["attack-action--2"],
        {"attack-action--2": {"order_basis": "explicit", "evidence_quote": QUOTE}},
    ),
    action(2),
)


def test_run_text_job_submits_polls_and_downloads():
    fake = FakeApi(AFB, polls=2)
    c = client(fake)
    afb, job_id, audit = c.run_text_job(
        "report text", {"title": "t"}, provider_id="prov", model="mod-1"
    )
    assert json.loads(afb) == AFB and job_id == "job-1"
    body = fake.jobs["job-1"]["body"]
    assert (
        body["options"] == {"provider_id": "prov", "model": "mod-1"}
        and body["input_type"] == "text"
    )
    assert api.provider_from_audit(audit) == ("prov", "mod-1")
    assert [
        r for r in fake.requests if r[1] == "/jobs/job-1"
    ].__len__() == 3  # 2 running, 1 completed


def test_failed_job_and_missing_artifact_raise():
    for mode, code in (("fail", "extraction_output_malformed"), ("no-afb", None)):
        with pytest.raises(api.JobFailed) as e:
            client(FakeApi(AFB, {"t": mode})).run_text_job("x", {"title": "t"})
        assert e.value.job_id == "job-1" and e.value.code == code


def test_wait_times_out():
    ticks = iter(range(0, 10_000, 100))
    c = api.ApiClient(
        "http://api.test/api/v1",
        transport=httpx.MockTransport(FakeApi(AFB, polls=10**6)),
        sleep=lambda s: None,
        clock=lambda: next(ticks),
    )
    with pytest.raises(api.JobFailed, match="still running"):
        c.run_text_job("x", {"title": "t"}, timeout=500)


@pytest.fixture
def db(scratch_db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        conn.execute("INSERT INTO pivot.attack_version (version) VALUES ('t')")
        conn.execute(
            "INSERT INTO pivot.technique (attack_id, version, name) VALUES ('T1003.001', 't', 'x')"
        )
        conn.execute(
            "INSERT INTO pivot.source (name, publisher, source_class, default_tlp, enabled) VALUES ('Blog', 'Acme', 'vendor', 'clear', true)"
        )
        conn.commit()
        yield conn


def add_candidate(conn, title, sequence=True, published="2026-02-03"):
    source = conn.execute("SELECT * FROM pivot.source").fetchone()
    rid, _ = store.save_report(
        conn,
        source,
        text=f"{title} " + "body " * 200,
        title=title,
        url=f"https://x.example/{title}",
        published=published,
    )
    conn.execute(
        "UPDATE pivot.report SET triage_status = 'candidate', triage = %s::jsonb WHERE id = %s",
        (json.dumps({"llm": {"has_sequence_language": sequence}}), rid),
    )
    conn.commit()
    return rid


@pytest.mark.pivot_db
def test_pending_prefers_sequence_language_then_newest(db):
    add_candidate(db, "plain-new", sequence=False, published="2026-03-01")
    add_candidate(db, "seq-old", published="2026-01-01")
    add_candidate(db, "seq-new", published="2026-02-01")
    assert [r["title"] for r in run.pending(db)] == ["seq-new", "seq-old", "plain-new"]
    assert len(run.pending(db, limit=2)) == 2


@pytest.mark.pivot_db
def test_extract_ingests_flows_links_reports_and_logs_calls(db):
    ok1, ok2 = add_candidate(db, "a"), add_candidate(db, "b")
    bad, noafb = add_candidate(db, "c"), add_candidate(db, "d")
    fake = FakeApi(AFB, fail={"c": "fail", "d": "no-afb"})
    counts = run.extract_reports(db, client(fake), "t", concurrency=2)
    assert (counts["extracted"], counts["failed"], counts["transitions"]) == (2, 2, 2)

    status = {
        r["title"]: (r["triage_status"], r["triage_reason"])
        for r in db.execute(
            "SELECT title, triage_status, triage_reason FROM pivot.report"
        )
    }
    assert status["a"][0] == status["b"][0] == "extracted"
    assert (
        status["c"][0] == "failed" and "extraction_output_malformed" in status["c"][1]
    )
    assert status["d"][0] == "failed"

    flows = db.execute(
        "SELECT origin, llm_provider, llm_model, api_job_id, report_id, tlp FROM pivot.flow ORDER BY api_job_id"
    ).fetchall()
    assert len(flows) == 2 and {f["report_id"] for f in flows} == {ok1, ok2}
    assert all(
        f["origin"] == "llm"
        and f["llm_provider"] == "prov"
        and f["llm_model"] == "mod-1"
        for f in flows
    )
    t = db.execute(
        "SELECT order_basis, evidence_quote FROM pivot.transition_obs"
    ).fetchall()
    assert t == [{"order_basis": "explicit", "evidence_quote": QUOTE}] * 2

    calls = db.execute(
        "SELECT ok, provider, model, latency_ms, job_id IS NOT NULL AS has_job FROM pivot.llm_call WHERE purpose = 'extract' ORDER BY ok DESC"
    ).fetchall()
    assert [c["ok"] for c in calls] == [True, True, False, False]
    assert calls[0] == {
        "ok": True,
        "provider": "prov",
        "model": "mod-1",
        "latency_ms": 12000,
        "has_job": True,
    }

    sent = fake.jobs["job-1"]["body"]["metadata"]
    assert (
        sent["external_references"]
        and sent["authors"] == ["Acme"]
        and sent["source_name"] == "Blog"
    )
    assert (
        run.pending(db) == []
    )  # nothing left to extract; failed ones are not retried silently


@pytest.mark.pivot_db
def test_extract_fails_an_empty_flow_and_rolls_back_a_broken_ingest(db, monkeypatch):
    add_candidate(db, "a")
    empty = {"schema": "attack_flow_v2", "objects": []}
    counts = run.extract_reports(db, client(FakeApi(empty)), "t")
    assert counts["failed"] == 1 and counts["extracted"] == 0
    row = db.execute("SELECT triage_status, triage_reason FROM pivot.report").fetchone()
    assert (
        row["triage_status"] == "failed" and "no attack actions" in row["triage_reason"]
    )

    db.execute("UPDATE pivot.report SET triage_status = 'candidate'")
    db.commit()

    def boom(conn, *a, **k):
        conn.execute("INSERT INTO pivot.incident (label) VALUES ('half-written')")
        raise ValueError("ingest broke")

    monkeypatch.setattr(run.load, "ingest_flow", boom)
    assert run.extract_reports(db, client(FakeApi(AFB)), "t")["failed"] == 1
    assert db.execute("SELECT count(*) AS n FROM pivot.incident").fetchone()["n"] == 0


@pytest.mark.pivot_db
def test_cli_extract(scratch_db_url, capsys):
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    assert main([*url, "extract"]) == 1
    assert "afp attack sync" in capsys.readouterr().err
