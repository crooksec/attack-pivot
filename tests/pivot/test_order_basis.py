"""
P2.4 round trip, Python half: an extraction's per-link ``order_basis`` / ``evidence_quote`` survive
extraction -> canonical flow -> ``.afb`` export -> pivot parser (SPEC §5.3).
"""

import json

import pytest

from attack_flow_api.services.afb_export_contracts import assemble_afb_export_bundle
from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackActionNode,
    AttackFlowMetadata,
    LinkMeta,
    OrchestrationMode,
    SourceClassification,
    normalize_link_meta,
)
from attack_flow_api.services.afb_fusion_dedup import MergedAttackAction
from attack_flow_api.services.ai_output_validation_service import (
    _normalize_evidence_citations,
)
from attack_flow_api.services.canonical_flow_conversion_service import (
    build_canonical_flow_output,
)
from attack_pivot.ingest.afb import parse_afb

QUOTE = "The operator then dumped credentials from LSASS."


def action(i, effect_refs=(), link_meta=None, technique="T1003.001"):
    return AttackActionNode(
        id=f"attack-action--{i}",
        name=f"Step {i}",
        description=f"Observed step {i} exactly as reported.",
        confidence=0.8,
        technique={
            "technique_id": technique,
            "technique_name": "x",
            "confidence": 0.8,
            "grounded_by": "explicit_attack_id_in_source",
        },
        effect_refs=list(effect_refs),
        link_meta=link_meta or {},
        evidence=[
            {
                "source": "narrative",
                "excerpt": f"Observed step {i} exactly as reported.",
            }
        ],
    ).model_dump(mode="json")


def extraction(*actions):
    return AfbExtractionResult.model_validate(
        {
            "validation_state": "valid",
            "provider_invoked": True,
            "attack_flow": AttackFlowMetadata(
                id="attack-flow--rt",
                name="Round trip",
                scope="incident",
                description="d",
                orchestration_mode=OrchestrationMode.FULL_EXTRACTION,
                source_classification=SourceClassification.NARRATIVE_TEXT,
                start_refs=[actions[0]["id"]],
                authors=["a"],
                external_references=["https://example.com/r"],
            ).model_dump(mode="json"),
            "attack_actions": list(actions),
        }
    )


def exported_afb(*actions):
    canonical = build_canonical_flow_output(
        fused_output=None, extraction_output=extraction(*actions)
    )
    assert canonical is not None
    return assemble_afb_export_bundle(canonical).to_diagram_export_ready(), canonical


def test_link_labels_survive_extraction_to_afb_to_parser():
    afb, canonical = exported_afb(
        action(
            1,
            ["attack-action--2"],
            {"attack-action--2": {"order_basis": "explicit", "evidence_quote": QUOTE}},
        ),
        action(
            2, ["attack-action--3"], {"attack-action--3": {"order_basis": "timestamp"}}
        ),
        action(3),
    )
    edges = {
        (e.source_ref[-1], e.target_ref[-1]): e
        for e in canonical.edges
        if e.edge_type.value == "effect"
    }
    assert (
        edges[("1", "2")].order_basis == "explicit"
        and edges[("1", "2")].evidence_quote == QUOTE
    )

    lines = [o for o in afb["objects"] if o["id"] == "dynamic_line"]
    assert sorted(
        json.dumps(l["properties"]) for l in lines if l.get("properties")
    ) == sorted(
        [
            json.dumps([["x_order_basis", "explicit"], ["x_evidence_quote", QUOTE]]),
            json.dumps([["x_order_basis", "timestamp"]]),
        ]
    )
    parsed = parse_afb(afb)
    by_name = {a.node_ref: a.name for a in parsed.actions}
    got = {
        (by_name[e.src], by_name[e.dst]): (e.order_basis, e.evidence_quote)
        for e in parsed.edges
    }
    assert got == {
        ("Step 1", "Step 2"): ("explicit", QUOTE),
        ("Step 2", "Step 3"): ("timestamp", None),
    }


def test_unlabelled_links_stay_unlabelled():
    """No labels in -> no x_ properties out; the ingest then applies ``inferred_llm``."""
    afb, _ = exported_afb(action(1, ["attack-action--2"]), action(2))
    assert all(
        not o.get("properties") for o in afb["objects"] if o["id"] == "dynamic_line"
    )
    (edge,) = parse_afb(afb).edges
    assert (edge.order_basis, edge.evidence_quote) == (None, None)


def test_parser_drops_invalid_labels():
    afb, _ = exported_afb(
        action(
            1, ["attack-action--2"], {"attack-action--2": {"order_basis": "explicit"}}
        ),
        action(2),
    )
    line = next(o for o in afb["objects"] if o["id"] == "dynamic_line")
    line["properties"] = [["x_order_basis", "guessed"], ["x_evidence_quote", "y" * 500]]
    (edge,) = parse_afb(afb).edges
    assert edge.order_basis is None and len(edge.evidence_quote) == 200


def test_condition_path_takes_the_label_from_the_actions_own_line():
    """action -> (labelled) -> condition -> action: the induced edge carries the first line's label."""
    afb = {
        "schema": "attack_flow_v2",
        "objects": [
            {"id": "action", "instance": "a1", "anchors": {"270": "a1o"}, "properties": []},
            {"id": "condition", "instance": "c", "anchors": {"90": "ci", "branch:True": "ct"}, "properties": []},
            {"id": "action", "instance": "a2", "anchors": {"90": "a2i"}, "properties": []},
            {"id": "generic_anchor", "instance": "a1o", "latches": ["l1s"]},
            {"id": "generic_anchor", "instance": "ci", "latches": ["l1t"]},
            {"id": "generic_anchor", "instance": "ct", "latches": ["l2s"]},
            {"id": "generic_anchor", "instance": "a2i", "latches": ["l2t"]},
            {"id": "dynamic_line", "instance": "line1", "source": "l1s", "target": "l1t",
             "properties": [["x_order_basis", "inferred_narrative"], ["x_evidence_quote", "after the login"]]},
            {"id": "dynamic_line", "instance": "line2", "source": "l2s", "target": "l2t",
             "properties": [["x_order_basis", "explicit"]]},
        ],
    }  # fmt: skip
    (edge,) = parse_afb(afb).edges
    assert (edge.via, edge.order_basis, edge.evidence_quote) == (
        "condition_true", "inferred_narrative", "after the login",
    )  # fmt: skip


def test_normalize_link_meta():
    long_quote = "word " * 100
    out = normalize_link_meta(
        {
            "a": {"order_basis": "explicit", "evidence_quote": long_quote},
            "b": {"order_basis": "made-up", "evidence_quote": "  "},
            "c": {"order_basis": "timestamp"},
            "not-linked": {"order_basis": "explicit"},
            "d": "bad",
        },
        ["a", "b", "c", "d"],
    )
    assert out == {
        "a": {"order_basis": "explicit", "evidence_quote": long_quote.strip()[:200]},
        "c": {"order_basis": "timestamp"},
    }
    assert normalize_link_meta(None, ["a"]) == {}
    with pytest.raises(ValueError):
        LinkMeta(evidence_quote="x" * 201)


def test_validation_normalizes_provider_output_before_the_strict_model():
    merged = {
        "attack_actions": [
            {"id": "a", "effect_refs": ["b"], "link_meta": {"b": {"order_basis": "explicit", "evidence_quote": "q " * 300}}},
            {"id": "b", "effect_refs": []},
        ]
    }  # fmt: skip
    first = _normalize_evidence_citations(merged)["attack_actions"][0]
    assert len(first["link_meta"]["b"]["evidence_quote"]) == 200


def test_fusion_keeps_link_labels_for_ai_actions_and_adds_them_to_deterministic_ones():
    from attack_flow_api.services.afb_fusion_dedup import (
        merge_attack_actions_deterministic_first,
    )

    def item(i, refs=(), meta=None, desc="Observed command exactly as reported."):
        return {
            "id": f"attack-action--{i}",
            "name": f"S{i}",
            "description": desc,
            "confidence": 0.7,
            "effect_refs": list(refs),
            "link_meta": meta or {},
            "evidence": [{"source": "narrative", "excerpt": desc}],
        }

    label = {"attack-action--2": {"order_basis": "explicit", "evidence_quote": QUOTE}}
    ai_only = merge_attack_actions_deterministic_first(
        [], [item(1, ["attack-action--2"], label), item(2)]
    )
    assert ai_only[0].link_meta == label and ai_only[1].link_meta == {}

    # deterministic structure wins on refs; the AI's label for an existing link is kept,
    # and a label for a link the deterministic action does not have is dropped
    merged = merge_attack_actions_deterministic_first(
        [item(1, ["attack-action--2"])],
        [
            item(
                1,
                ["attack-action--2", "attack-action--9"],
                {**label, "attack-action--9": {"order_basis": "explicit"}},
            )
        ],
    )
    assert (
        merged[0].effect_refs == ["attack-action--2"] and merged[0].link_meta == label
    )

    # and the canonical flow built from fused output carries it onto the edge
    fused = extraction(*[item(1, ["attack-action--2"], label), item(2)])
    canonical = build_canonical_flow_output(fused_output=None, extraction_output=fused)
    (edge,) = [e for e in canonical.edges if e.edge_type.value == "effect"]
    assert (edge.order_basis, edge.evidence_quote) == ("explicit", QUOTE)


def test_fused_edges_carry_the_labels():
    from attack_flow_api.services.canonical_flow_conversion_service import (
        _build_edges_from_fused_output,
    )

    a1 = MergedAttackAction(
        id="attack-action--1", name="a", description="d", confidence=0.5,
        effect_refs=["attack-action--2"],
        link_meta={"attack-action--2": {"order_basis": "timestamp", "evidence_quote": QUOTE}},
    )  # fmt: skip
    edges = _build_edges_from_fused_output([], [a1], [], [], [], [])
    assert [(e.order_basis, e.evidence_quote) for e in edges] == [("timestamp", QUOTE)]


@pytest.mark.pivot_db
def test_ingest_of_an_extracted_flow(scratch_db_url):
    from datetime import date

    from attack_pivot.db import connect
    from attack_pivot.db import migrate as migrations
    from attack_pivot.ingest import load
    from attack_pivot.normalize.attack import TechniqueIndex

    afb, _ = exported_afb(
        action(1, ["attack-action--2"], {"attack-action--2": {"order_basis": "timestamp", "evidence_quote": QUOTE}}),
        action(2, ["attack-action--3"]),  # unlabelled link
        action(3),
    )  # fmt: skip
    with connect(scratch_db_url) as conn:
        migrations.migrate(conn)
        source = load.ensure_source(conn, load.MANUAL_SOURCE)
        report = conn.execute(
            "INSERT INTO pivot.report (source_id, url, published_at, sha256, tlp, triage_status) "
            "VALUES (%s, 'https://x.example/r', '2026-02-03', 'abc', 'clear', 'candidate') RETURNING id",
            (source,),
        ).fetchone()["id"]
        counts = load.ingest_flow(
            conn, parse_afb(afb), afb, "afb", path_name="x", sha256="abc", version="t",
            index=TechniqueIndex({"T1003.001"}, {}), source_id=source, tlp="clear",
            report_id=report, llm={"provider": "p", "model": "m", "job_id": "job-1"},
        )  # fmt: skip
        assert counts["transitions"] == 2
        rows = conn.execute(
            "SELECT a.name AS src, t.order_basis, t.evidence_quote FROM pivot.transition_obs t "
            "JOIN pivot.action_obs a ON a.id = t.src_action ORDER BY a.name"
        ).fetchall()
        assert rows == [
            {"src": "Step 1", "order_basis": "timestamp", "evidence_quote": QUOTE},
            {"src": "Step 2", "order_basis": "inferred_llm", "evidence_quote": None},
        ]
        flow = conn.execute(
            "SELECT origin, llm_provider, llm_model, api_job_id, review_status, report_id FROM pivot.flow"
        ).fetchone()
        assert flow == {"origin": "llm", "llm_provider": "p", "llm_model": "m", "api_job_id": "job-1", "review_status": "unreviewed", "report_id": report}  # fmt: skip
        assert (
            conn.execute("SELECT triage_status FROM pivot.report").fetchone()[
                "triage_status"
            ]
            == "extracted"
        )
        # no timestamps in the flow: the incident takes the report's publication date
        inc = conn.execute(
            "SELECT first_seen, last_seen FROM pivot.incident"
        ).fetchone()
        assert inc == {"first_seen": date(2026, 2, 3), "last_seen": date(2026, 2, 3)}
