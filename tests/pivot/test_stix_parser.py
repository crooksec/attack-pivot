from pathlib import Path

import pytest

from attack_pivot.ingest.stix import parse_stix, parse_stix_file

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
TS = "2022-08-02T19:34:35.143Z"


def _obj(kind, n, **props):
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--00000000-0000-4000-8000-{n:012d}",
        "created": TS,
        "modified": TS,
        **props,
    }


def _id(kind, n):
    return f"{kind}--00000000-0000-4000-8000-{n:012d}"


def _bundle(*objects):
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000999",
        "objects": list(objects),
    }


@pytest.mark.parametrize(
    "name,flow,actions,edges",
    [
        ("flow1.json", "Test Flow 1", 2, 1),
        ("flow2.json", "Test Flow 2", 2, 1),
        ("badflow1.json", "Test Flow 1", 2, 1),  # schema-invalid, still parseable
        ("badflow2.json", "Test Flow 2", 2, 1),
        ("matrix-flow.json", "Tesla Kubernetes Breach", 6, 4),
    ],
)
def test_repo_fixtures_ingest(name, flow, actions, edges):
    parsed = parse_stix_file(FIXTURES / name)
    assert parsed.name == flow
    assert (len(parsed.actions), len(parsed.edges)) == (actions, edges)
    assert all(e.via == "direct" for e in parsed.edges)
    assert all(a.label_source == "technique_id" for a in parsed.actions)


def test_creator_identities_are_not_sectors():
    assert parse_stix_file(FIXTURES / "matrix-flow.json").sectors == []


def test_upstream_example_with_operator_and_conditions():
    parsed = parse_stix_file(ROOT / "stix" / "attack-flow-example.json")
    assert len(parsed.actions) == 5
    assert [e.via for e in parsed.edges] == ["condition_true"] * 4


def test_via_classification():
    a, b, c, d, e = (_id("attack-action", i) for i in range(1, 6))
    and_, or_, cond = (
        _id("attack-operator", 1),
        _id("attack-operator", 2),
        _id("attack-condition", 1),
    )
    bundle = _bundle(
        _obj(
            "attack-action",
            1,
            technique_id="T1566",
            name="a",
            effect_refs=[b, and_, or_, cond],
        ),
        _obj("attack-action", 2, technique_id="T1204", name="b"),
        _obj("attack-operator", 1, operator="AND", effect_refs=[c]),
        _obj("attack-operator", 2, operator="OR", effect_refs=[d]),
        _obj("attack-condition", 1, description="x", on_false_refs=[e]),
        _obj("attack-action", 3, technique_id="T1059", name="c"),
        _obj("attack-action", 4, technique_id="T1105", name="d"),
        _obj("attack-action", 5, name="e", tactic_id="TA0008"),
    )
    parsed = parse_stix(bundle)
    assert {(e.dst, e.via) for e in parsed.edges if e.src == a} == {
        (b, "direct"),
        (c, "and"),
        (d, "or"),
        (e, "condition_false"),
    }
    assert parsed.action(e).label_source == "tactic_only"


def test_unparseable_object_is_an_error():
    bundle = _bundle(
        _obj("attack-action", 1, name="a", technique_id="T1", effect_refs=["bogus"])
    )
    with pytest.raises(Exception):
        parse_stix(bundle)
