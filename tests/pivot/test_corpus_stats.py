import json

import pytest

from attack_pivot.cli import main
from attack_pivot.corpus import stats

pytestmark = pytest.mark.pivot_db


def test_stats_on_the_seed_corpus(corpus_db):
    s = stats.stats(corpus_db, "test")
    assert (s["incidents"], s["flows"], s["incidents_with_ordered_transitions"]) == (
        38,
        38,
        38,
    )
    assert s["by_source_class"] == {"emulation": 2, "independent": 36}
    assert s["by_tlp"] == {"clear": 38}
    assert s["reports"]["total"] == 41 and s["reports"]["by_status"] == {
        "extracted": 41
    }
    assert s["flows_by_origin"] == {"upstream_corpus": 41}
    assert (
        s["incident_level_transitions"] > 0
        and s["unique_transition_pairs"] <= s["incident_level_transitions"]
    )
    assert (
        s["pairs_with_n_ge"]["2"]
        >= s["pairs_with_n_ge"]["5"]
        >= s["pairs_with_n_ge"]["10"]
    )
    assert s["unique_techniques"] > 100
    assert {a["actor"] for a in s["top_actors"]} >= {"Turla", "FIN13"}
    assert s["review"]["reviewed_flows"] == 0 and s["review"]["llm_flows"] == 0
    assert s["vcdb"] == {"incidents": 0, "with_sequence": 0}


def test_progress_is_measured_against_both_milestones(corpus_db):
    s = stats.stats(corpus_db, "test")
    proof, stretch = s["progress"]["M-Proof"], s["progress"]["M-Stretch"]
    assert proof["incidents"] == {"have": 38, "target": 500, "pct": 7.6}
    assert (
        stretch["incidents"]["target"] == 2000
        and stretch["transitions"]["target"] == 20000
    )
    assert proof["transitions"]["have"] == pytest.approx(
        s["incident_level_transitions"], abs=1e-3
    )


def test_vcdb_sequence_incidents_are_a_separate_line(corpus_db):
    before = stats.stats(corpus_db, "test")
    corpus_db.execute(
        "INSERT INTO pivot.veris_incident (id, has_sequence, year) VALUES ('a', true, 2020), ('b', false, 2021)"
    )
    corpus_db.commit()
    after = stats.stats(corpus_db, "test")
    assert after["vcdb"] == {"incidents": 2, "with_sequence": 1}
    assert (
        after["progress"] == before["progress"]
        and after["incidents"] == before["incidents"]
    )


def test_requires_an_attack_version(scratch_db_url):
    from attack_pivot.db import connect
    from attack_pivot.db import migrate as migrations

    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        with pytest.raises(RuntimeError, match="afp attack sync"):
            stats.stats(conn)


def test_render_and_cli(corpus_db, scratch_db_url, capsys):
    text = stats.render(stats.stats(corpus_db, "test"))
    assert "M-Proof: incidents 38/500 (7.6%)" in text and "VCDB (separate" in text
    assert "no edges reviewed yet" in text
    assert (
        main(
            [
                "--database-url",
                scratch_db_url,
                "corpus",
                "stats",
                "--attack-version",
                "test",
                "--json",
            ]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)
    assert (
        out["incidents"] == 38
        and out["progress"]["M-Proof"]["incidents"]["target"] == 500
    )
