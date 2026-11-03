import json
from pathlib import Path

import pytest

from attack_pivot.ingest.afb import parse_afb, parse_afb_file

ROOT = Path(__file__).resolve().parents[2]
CORPUS = sorted((ROOT / "corpus").glob("*.afb"))
GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures" / "afb_golden.json").read_text()
)

# The 7 flows that the naive resolver reported as 0 edges (SPEC §5.1.6). Their lines resolve;
# six carry their technique only in ``ttp`` (the two OpenClaw flows use MITRE ATLAS IDs, not
# ATT&CK Enterprise); "Example Attack Tree" has no technique labels at all.
ZERO_EDGE_FLOWS = {
    "Example Attack Tree": "none",
    "Turla - Carbon Emulation Plan": "ttp",
    "Turla - Snake Emulation Plan": "ttp",
    "OpenClaw": "ttp",
    "OpenClaw Command & Control via Prompt Injection": "ttp",
    "ToolShell Vulnerability in Sharepoint": "ttp",
    "Equifax Breach": "ttp",
}


class Afb:
    """Tiny .afb builder: each node gets one anchor with one latch."""

    def __init__(self):
        self.objects, self.n = [], 0

    def node(self, kind, anchors=("0",), **props):
        self.n += 1
        ref = f"n{self.n}"
        anchor_ids = {}
        for key in anchors:
            aid, lid = f"{ref}-a{key}", f"{ref}-l{key}"
            anchor_ids[key] = aid
            self.objects.append(
                {"id": "vertical_anchor", "instance": aid, "latches": [lid]}
            )
            self.objects.append({"id": "generic_latch", "instance": lid})
        self.objects.append(
            {
                "id": kind,
                "instance": ref,
                "anchors": anchor_ids,
                "properties": [[k, v] for k, v in props.items()],
            }
        )
        return ref

    def line(self, src, dst, src_key="0"):
        self.objects.append(
            {
                "id": "dynamic_line",
                "instance": f"line{len(self.objects)}",
                "source": f"{src}-l{src_key}",
                "target": f"{dst}-l0",
            }
        )

    def build(self):
        return {"schema": "attack_flow_v2", "objects": self.objects}


def test_via_classification():
    b = Afb()
    a = b.node("action", technique_id="T1566")
    and_ = b.node("AND_operator")
    or_ = b.node("OR_operator")
    cond = b.node("condition", anchors=("0", "branch:True", "branch:False"))
    d, e, t, f = (b.node("action", technique_id=f"T10{i}") for i in range(4))
    b.line(a, d)
    b.line(a, and_)
    b.line(and_, e)
    b.line(a, or_)
    b.line(or_, t)
    b.line(a, cond)
    b.line(cond, f, "branch:False")
    parsed = parse_afb(b.build())
    got = {(e.dst, e.via) for e in parsed.edges if e.src == a}
    assert got == {(d, "direct"), (e, "and"), (t, "or"), (f, "condition_false")}


def test_first_pass_through_node_wins_and_cycles_terminate():
    b = Afb()
    a = b.node("action", technique_id="T1")
    cond = b.node("condition", anchors=("0", "branch:True", "branch:False"))
    and_ = b.node("AND_operator")
    x = b.node("action", technique_id="T2")
    b.line(a, cond)
    b.line(cond, and_, "branch:True")
    b.line(and_, x)
    b.line(and_, cond)  # cycle through the pass-through nodes
    parsed = parse_afb(b.build())
    assert [(e.src, e.dst, e.via) for e in parsed.edges] == [(a, x, "condition_true")]


def test_label_resolution_order_and_confidence():
    b = Afb()
    b.node("action", technique_id="T1059.001", tactic_id="TA0002", confidence="certain")
    b.node("action", ttp=[["tactic", "TA0011"], ["technique", "T1105"]])
    b.node("action", ttp=[["tactic", "TA0008"], ["technique", None]])
    b.node("action", name="free text")
    by_ref = {a.node_ref: a for a in parse_afb(b.build()).actions}
    assert [(a.technique_id, a.tactic_id, a.label_source) for a in by_ref.values()] == [
        ("T1059.001", "TA0002", "technique_id"),
        ("T1105", "TA0011", "ttp"),
        (None, "TA0008", "tactic_only"),
        (None, None, "none"),
    ]
    assert by_ref["n1"].confidence == 100


def test_context_extraction():
    b = Afb()
    b.node("threat_actor", name="OceanLotus", aliases=["APT32"])
    b.node("campaign", name="Operation Cobalt Kitty")
    b.node("identity", name="Org", sectors=[["abc", "Utilities"]])
    b.node("location", name="Brazil", country="Brazil")
    parsed = parse_afb(b.build())
    assert parsed.actors == [
        {"name": "OceanLotus", "aliases": ["APT32"], "type": "threat_actor"}
    ]
    assert parsed.campaigns == ["Operation Cobalt Kitty"]
    assert parsed.sectors == ["Utilities"] and parsed.regions == ["Brazil"]


def test_corpus_has_41_files_and_golden_entries():
    assert len(CORPUS) == 41
    assert {p.name for p in CORPUS} == set(GOLDEN)


@pytest.mark.parametrize("path", CORPUS, ids=lambda p: p.stem)
def test_golden_counts(path):
    assert parse_afb_file(path).stats == GOLDEN[path.name]


def test_corpus_totals_match_independent_count():
    """1,070 action→action pairs, counted separately with a standalone script during P0 triage."""
    stats = [GOLDEN[p.name] for p in CORPUS]
    assert sum(s["actions"] for s in stats) == 952
    assert sum(s["action_pairs"] for s in stats) == 1070


@pytest.mark.parametrize("stem,label", sorted(ZERO_EDGE_FLOWS.items()))
def test_previously_zero_edge_flows(stem, label):
    parsed = parse_afb_file(ROOT / "corpus" / f"{stem}.afb")
    assert parsed.stats["action_pairs"] > 0
    if label == "ttp":
        assert parsed.stats["labels"].get("ttp", 0) > 0
        assert parsed.stats["labeled_pairs"] > 0
    else:
        assert parsed.stats["labeled_pairs"] == 0
