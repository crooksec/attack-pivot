import csv
import json

import pytest

from attack_pivot import llm
from attack_pivot.cli import main
from attack_pivot.collect import store
from attack_pivot.db import connect
from attack_pivot.db import migrate as migrations
from attack_pivot.normalize.attack import TechniqueIndex
from attack_pivot.triage import classify, evaluate, heuristics, run

INDEX = TechniqueIndex(
    valid={"T1566", "T1566.001", "T1059.001", "T1003.001", "T1685"},
    replaced_by={"T1562": "T1685", "T1086": "T1059.001"},
)
FILLER = " ".join(
    f"Unrelated sentence number {i} about the weather." for i in range(60)
)
NARRATIVE = (
    "The threat actor sent a phishing email. Then we observed PowerShell run on the host, "
    "followed by Mimikatz reading LSASS. Later the attacker used PsExec for lateral movement "
    "and a Cobalt Strike beacon for command and control, and finally ransomware encrypted files. "
    "After 2 hours the adversary exfiltrated data. 10:42 first login, 10:55 second login. "
)


class FakeLlm:
    provider_id, model = "fake", "fake-1"

    def __init__(self, answer):
        self.answer, self.prompts = answer, []

    def complete_json(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return self.answer, {"input_tokens": 100, "output_tokens": 20, "latency_ms": 7}


def test_technique_mentions_normalize_and_drop_unknown():
    text = (
        "T1566.001, T1086 (old), T1562, T1566.001 again, AML.T0051, T9999, T1003.001."
    )
    assert heuristics.technique_mentions(text, INDEX) == {
        "T1566.001", "T1059.001", "T1685", "T1003.001",
    }  # fmt: skip


def test_first_pass():
    stats = heuristics.analyze(NARRATIVE * 3 + FILLER, INDEX)
    assert stats["technique_mentions"] == 0
    assert len(stats["behaviour_categories"]) >= 6 and stats["sequence_heuristic"]
    assert heuristics.first_pass(stats) == (True, "heuristic:behaviour_vocabulary")
    cited = heuristics.analyze("T1566 T1059.001 T1003.001 " + FILLER, INDEX)
    assert heuristics.first_pass(cited) == (True, "heuristic:cites_techniques")
    assert heuristics.first_pass(heuristics.analyze(FILLER, INDEX)) == (
        False, "heuristic:no_intrusion_signal",
    )  # fmt: skip
    assert heuristics.first_pass(heuristics.analyze("short", INDEX)) == (
        False,
        "heuristic:too_short",
    )


def test_parse_answer_is_strict():
    ok = {
        "is_intrusion_narrative": True,
        "technique_count_estimate": "6",
        "has_sequence_language": True,
        "reason": "r",
    }
    assert classify.parse_answer(ok)["technique_count_estimate"] == 6
    assert classify.parse_answer({**ok, "is_intrusion_narrative": "yes"}) is None
    assert classify.parse_answer({**ok, "technique_count_estimate": "many"}) is None
    assert classify.parse_answer({**ok, "technique_count_estimate": True}) is None
    assert (
        classify.parse_answer({**ok, "technique_count_estimate": 9999})[
            "technique_count_estimate"
        ]
        == 200
    )
    assert classify.parse_answer([1]) is None


def test_excerpt_keeps_head_and_tail():
    text = "A" * 9000 + "B" * 20000 + "C" * 3000
    out = classify.excerpt(text)
    assert (
        len(out) < 12100
        and out.startswith("A")
        and out.endswith("C")
        and "[...]" in out
    )
    assert classify.excerpt("short") == "short"


def test_decide():
    s = {"technique_mentions": 1}
    yes = {"is_intrusion_narrative": True, "technique_count_estimate": 5}
    assert run.decide(s, yes) == ("candidate", "llm:intrusion_narrative;techniques=5")
    assert run.decide(s, {**yes, "technique_count_estimate": 2})[0] == "rejected"
    assert (
        run.decide({"technique_mentions": 4}, {**yes, "technique_count_estimate": 1})[0]
        == "candidate"
    )
    assert run.decide(s, {**yes, "is_intrusion_narrative": False}) == (
        "rejected",
        "llm:not_intrusion_narrative",
    )
    assert run.decide({"technique_mentions": 3}, None)[0] == "candidate"
    assert run.decide(s, None)[0] == "rejected"


def test_parse_json_object_tolerates_fences():
    assert llm.parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.parse_json_object("no json") is None
    assert llm.parse_json_object("[1,2]") is None


def test_from_config_errors(tmp_path):
    with pytest.raises(llm.LlmUnavailable, match="no provider config"):
        llm.from_config(config_path=tmp_path / "nope.yml")
    path = tmp_path / "p.yml"
    path.write_text(
        "providers:\n  - {provider_id: o, provider_type: openai, enabled: false, api_key_env: K, default_model: m}\n"
    )
    with pytest.raises(llm.LlmUnavailable, match="no enabled provider"):
        llm.from_config(config_path=path)


def test_llm_client_calls_the_adapter():
    from attack_flow_api.providers.contracts import (
        ProviderTokenUsage,
        StructuredGenerationResult,
    )

    class Adapter:
        def generate_structured(self, request):
            assert request.temperature == 0.0 and request.model == "m"
            return StructuredGenerationResult(
                provider_id="p", provider_type="openai", model="m", output_text='x {"ok": true} y',
                usage=ProviderTokenUsage(input_tokens=11, output_tokens=3), latency_ms=5,
            )  # fmt: skip

    obj, usage = llm.LlmClient(Adapter(), "p", "openai", "m").complete_json("hi")
    assert obj == {"ok": True} and usage == {
        "input_tokens": 11,
        "output_tokens": 3,
        "latency_ms": 5,
    }


@pytest.fixture
def db(scratch_db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        conn.execute(
            "INSERT INTO pivot.source (name, source_class, default_tlp, enabled) VALUES ('Blog', 'vendor', 'clear', true), ('Gov', 'government', 'clear', true)"
        )
        conn.commit()
        yield conn


def add(conn, text, source="Blog", title="t"):
    row = conn.execute(
        "SELECT * FROM pivot.source WHERE name = %s", (source,)
    ).fetchone()
    rid, _ = store.save_report(
        conn, row, text=text, title=title, url=f"https://x.example/{abs(hash(text))}"
    )
    conn.commit()
    return rid


def row(conn, rid):
    return conn.execute("SELECT * FROM pivot.report WHERE id = %s", (rid,)).fetchone()


@pytest.mark.pivot_db
def test_triage_with_llm_logs_cost_and_records_the_decision(db):
    good = add(db, NARRATIVE * 3 + FILLER, title="good")
    junk = add(db, FILLER, title="junk")
    fake = FakeLlm(
        {
            "is_intrusion_narrative": True,
            "technique_count_estimate": 7,
            "has_sequence_language": True,
            "reason": "ok",
        }
    )
    counts = run.triage_reports(db, INDEX, fake)
    assert (counts["candidate"], counts["rejected"], counts["llm_calls"]) == (1, 1, 1)
    r = row(db, good)
    assert r["triage_status"] == "candidate" and r["triage_reason"].startswith("llm:")
    assert (
        r["triage"]["mode"] == "llm"
        and r["triage"]["llm"]["technique_count_estimate"] == 7
    )
    assert row(db, junk)["triage_reason"] == "heuristic:no_intrusion_signal"
    assert (
        len(fake.prompts) == 1 and "REPORT:" in fake.prompts[0]
    )  # junk never reached the LLM
    cost = llm.cost_summary(db, "triage")
    assert cost == [
        {
            "purpose": "triage",
            "provider": "fake",
            "model": "fake-1",
            "calls": 1,
            "failed": 0,
            "input_tokens": 100,
            "output_tokens": 20,
        }
    ]
    assert run.triage_reports(db, INDEX, fake)["llm_calls"] == 0  # already decided


@pytest.mark.pivot_db
def test_unusable_llm_answer_leaves_the_report_new(db):
    rid = add(db, NARRATIVE * 3 + FILLER)
    counts = run.triage_reports(db, INDEX, FakeLlm({"nonsense": 1}))
    assert counts["llm_failed"] == 1 and row(db, rid)["triage_status"] == "new"
    assert llm.cost_summary(db)[0]["failed"] == 1

    class Boom:
        provider_id, model = "fake", "fake-1"

        def complete_json(self, *a, **k):
            raise TimeoutError("slow")

    assert run.triage_reports(db, INDEX, Boom())["llm_failed"] == 1
    assert row(db, rid)["triage_status"] == "new"


@pytest.mark.pivot_db
def test_heuristics_only_mode_is_marked(db):
    cited = add(db, "T1566 T1059.001 T1003.001 " + FILLER)
    counts = run.triage_reports(db, INDEX, None)
    r = row(db, cited)
    assert counts["candidate"] == 1 and r["technique_mentions"] == 3
    assert r["triage"]["mode"] == "heuristics_only" and "llm" not in r["triage"]


@pytest.mark.pivot_db
def test_precision_evaluation(db, tmp_path):
    ids = []
    for i in range(10):
        ids.append(
            add(
                db,
                f"T1566 T1059.001 T1003.001 {i} " + FILLER,
                source="Blog" if i % 2 else "Gov",
                title=f"c{i}",
            )
        )
    ids.append(add(db, "other " + FILLER, title="n"))
    run.triage_reports(db, INDEX, None)
    # reviewer says 8 of the 10 candidates are real and the rejected one is not
    truth = {str(i): (n < 8) for n, i in enumerate(ids[:10])} | {str(ids[10]): False}
    result = evaluate.evaluate(db, truth)
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (8, 2, 1, 0)
    assert result["precision"] == 0.8 and result["passes"]
    worse = evaluate.evaluate(db, {k: (n < 7) for n, k in enumerate(list(truth)[:10])})
    assert not worse["passes"]
    sample = evaluate.sample(db, n=6, seed=1)
    assert len(sample) == 6 and {s["source_class"] for s in sample} == {
        "vendor",
        "government",
    }
    assert [s["id"] for s in sample] == [
        s["id"] for s in evaluate.sample(db, n=6, seed=1)
    ]
    out = tmp_path / "s.csv"
    evaluate.write_sample(sample, out)
    header = next(csv.reader(out.open()))
    assert (
        "label" in header and "triage_status" not in header and "decision" not in header
    )
    with pytest.raises(RuntimeError, match="not yes/no"):
        out.write_text("report_id,label\nx,maybe\n")
        evaluate.read_labels(out)


@pytest.mark.pivot_db
def test_cli_triage(scratch_db_url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    url = ["--database-url", scratch_db_url]
    assert main([*url, "db", "init"]) == 0
    assert main([*url, "triage", "--heuristics-only"]) == 1  # no ATT&CK version yet
    assert "afp attack sync" in capsys.readouterr().err
    with connect(scratch_db_url) as conn:
        conn.execute("INSERT INTO pivot.attack_version (version) VALUES ('t')")
        conn.execute(
            "INSERT INTO pivot.technique (attack_id, version, name) VALUES ('T1566', 't', 'x')"
        )
        conn.commit()
    assert main([*url, "triage", "--heuristics-only"]) == 0
    assert "nothing to do" in capsys.readouterr().out
    monkeypatch.chdir(tmp_path)  # no config/providers.yml here
    assert main([*url, "triage"]) == 1
    assert "--heuristics-only" in capsys.readouterr().err
    assert main([*url, "triage", "cost"]) == 0
