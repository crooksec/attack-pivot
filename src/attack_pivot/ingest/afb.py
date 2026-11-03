"""Parse Attack Flow Builder ``.afb`` files into action graphs (SPEC §5.1)."""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Nodes that carry sequence between actions; anything else is context, not sequence.
PASS_THROUGH = {"AND_operator": "and", "OR_operator": "or", "condition": "condition"}
ACTION = "action"
ACTOR_TYPES = ("threat_actor", "intrusion_set")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Builder confidence terms (AttackFlowTemplates/ConfidenceProperty.ts).
CONFIDENCE = {
    "ai-generated": 0,
    "speculative": 10,
    "very-doubtful": 20,
    "doubtful": 30,
    "even-odds": 50,
    "probable": 70,
    "very-probable": 90,
    "certain": 100,
}


@dataclass
class ParsedAction:
    node_ref: str
    name: str | None
    technique_id: str | None  # as extracted, un-normalized
    tactic_id: str | None
    label_source: str  # technique_id | ttp | tactic_only | none
    confidence: int | None = None
    execution_start: str | None = None
    execution_end: str | None = None


@dataclass
class ParsedEdge:
    src: str
    dst: str
    via: str  # direct | and | or | condition_true | condition_false
    order_basis: str | None = None  # from the line's x_order_basis (SPEC §5.3)
    evidence_quote: str | None = None  # from x_evidence_quote, at most 200 characters


@dataclass
class ParsedFlow:
    name: str
    schema: str
    actions: list[ParsedAction] = field(default_factory=list)
    edges: list[ParsedEdge] = field(default_factory=list)
    actors: list[dict] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)

    def action(self, node_ref):
        return next(a for a in self.actions if a.node_ref == node_ref)

    @property
    def stats(self):
        """Counts used for golden tests and corpus notes."""
        by_ref = {a.node_ref: a for a in self.actions}
        labels = defaultdict(int)
        for a in self.actions:
            labels[a.label_source] += 1
        pairs = {(e.src, e.dst) for e in self.edges}
        labeled = {
            (by_ref[s].technique_id, by_ref[d].technique_id)
            for s, d in pairs
            if by_ref[s].technique_id and by_ref[d].technique_id
        }
        return {
            "actions": len(self.actions),
            "edges": len(self.edges),
            "action_pairs": len(pairs),
            "labeled_pairs": sum(
                1 for s, d in pairs if by_ref[s].technique_id and by_ref[d].technique_id
            ),
            "unique_transitions": len(labeled),
            "labels": dict(labels),
        }


def _props(obj):
    """Object properties as a dict. The Builder stores them as ``[[key, value], ...]``."""
    raw = obj.get("properties")
    if isinstance(raw, dict):
        return raw
    return {k: v for k, v in (raw or []) if isinstance(k, str)}


def _clean(value):
    return value if value not in (None, "") else None


ORDER_BASES = {"explicit", "timestamp", "inferred_narrative", "unordered"}
EVIDENCE_QUOTE_MAX = 200


def _link_meta(line):
    """``(order_basis, evidence_quote)`` from a line's ``x_`` properties; invalid values are dropped."""
    props = _props(line)
    basis = props.get("x_order_basis")
    quote = props.get("x_evidence_quote")
    return (
        basis if basis in ORDER_BASES else None,
        (
            " ".join(quote.split())[:EVIDENCE_QUOTE_MAX]
            if isinstance(quote, str) and quote.strip()
            else None
        ),
    )


def _pair_values(value):
    """Enum-list properties are ``[[hash, text], ...]``; return the texts."""
    return [v[1] for v in value or [] if isinstance(v, list) and len(v) == 2 and v[1]]


def _build_action(obj):
    p = _props(obj)
    ttp = dict(p.get("ttp") or [])
    technique = _clean(p.get("technique_id"))
    if technique:
        source = "technique_id"
    elif _clean(ttp.get("technique")):
        technique, source = ttp["technique"], "ttp"
    else:
        source = "none"
    tactic = _clean(p.get("tactic_id")) or _clean(ttp.get("tactic"))
    if source == "none" and tactic:
        source = "tactic_only"
    return ParsedAction(
        node_ref=obj["instance"],
        name=_clean(p.get("name")),
        technique_id=technique,
        tactic_id=tactic,
        label_source=source,
        confidence=CONFIDENCE.get(p.get("confidence")),
        execution_start=_clean(p.get("execution_start")),
        execution_end=_clean(p.get("execution_end")),
    )


def parse_afb(data, name=None):
    """
    Parse one ``.afb`` document.

    Resolution is line → latch → anchor → owner node. Action→action edges are induced by a
    DFS through AND/OR/condition nodes; ``via`` comes from the first pass-through node on the
    path. For a condition it is ``condition_true`` or ``condition_false`` according to the
    ``branch:True`` / ``branch:False`` anchor that the outgoing line leaves from (other
    anchors count as ``condition_true``).

    :param dict data: Parsed ``.afb`` JSON.
    :param str name: Fallback flow name.
    :rtype: ParsedFlow
    """
    objs = {o["instance"]: o for o in data.get("objects", []) if "instance" in o}
    anchor_owner, anchor_key, latch_anchor = {}, {}, {}
    for obj in objs.values():
        for key, anchor in (obj.get("anchors") or {}).items():
            anchor_owner[anchor] = obj["instance"]
            anchor_key[anchor] = key
    for obj in objs.values():
        for latch in obj.get("latches") or []:
            latch_anchor[latch] = obj["instance"]

    def endpoint(latch):
        anchor = latch_anchor.get(latch)
        return anchor_owner.get(anchor), anchor_key.get(anchor)

    outgoing = defaultdict(
        list
    )  # owner -> [(target owner, source anchor key, link meta)]
    for obj in objs.values():
        if obj["id"] != "dynamic_line":
            continue
        src, key = endpoint(obj.get("source"))
        dst, _ = endpoint(obj.get("target"))
        if src and dst:
            outgoing[src].append((dst, key, _link_meta(obj)))
        else:
            logger.warning("unresolved dynamic_line %s", obj["instance"])

    flow_obj = next((o for o in objs.values() if o["id"] == "flow"), None)
    flow_name = (flow_obj and _clean(_props(flow_obj).get("name"))) or name or "unnamed"
    parsed = ParsedFlow(name=flow_name, schema=data.get("schema", ""))
    parsed.actions = [_build_action(o) for o in objs.values() if o["id"] == ACTION]

    seen_edges = set()
    for action in parsed.actions:
        # the label on an induced edge is the one on the action's own outgoing line
        stack = [(t, None, k, meta) for t, k, meta in outgoing[action.node_ref]]
        visited = set()
        while stack:
            node, via, key, meta = stack.pop()
            kind = objs[node]["id"]
            if kind == ACTION:
                edge = (action.node_ref, node, via or "direct")
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    parsed.edges.append(ParsedEdge(*edge, *meta))
            elif kind in PASS_THROUGH:
                if via is None and kind == "condition":
                    # via depends on which branch each outgoing line leaves from
                    for target, k, _ in outgoing[node]:
                        v = (
                            "condition_false"
                            if k == "branch:False"
                            else "condition_true"
                        )
                        stack.append((target, v, k, meta))
                    continue
                v = via or PASS_THROUGH[kind]
                if (node, v) in visited:
                    continue
                visited.add((node, v))
                stack.extend((t, v, k, meta) for t, k, _ in outgoing[node])
    parsed.edges.sort(key=lambda e: (e.src, e.dst, e.via))

    _extract_context(parsed, objs.values())
    return parsed


def _extract_context(parsed, objects):
    for obj in objects:
        kind, p = obj["id"], _props(obj)
        if kind in ACTOR_TYPES and _clean(p.get("name")):
            parsed.actors.append(
                {
                    "name": p["name"],
                    "aliases": list(p.get("aliases") or []),
                    "type": kind,
                }
            )
        elif kind == "campaign" and _clean(p.get("name")):
            parsed.campaigns.append(p["name"])
        elif kind == "identity":
            parsed.sectors.extend(_pair_values(p.get("sectors")))
        elif kind == "location":
            region = (
                _clean(p.get("country"))
                or _clean(p.get("region"))
                or _clean(p.get("name"))
            )
            if region:
                parsed.regions.append(region)
    parsed.sectors = list(dict.fromkeys(parsed.sectors))
    parsed.regions = list(dict.fromkeys(parsed.regions))


def parse_afb_file(path):
    """
    Parse an ``.afb`` file, using the file name as the fallback flow name.

    :param Path path:
    :rtype: ParsedFlow
    """
    path = Path(path)
    return parse_afb(json.loads(path.read_text()), name=path.stem)
