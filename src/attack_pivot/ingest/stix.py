"""Parse Attack Flow STIX bundles into action graphs (SPEC §5.2)."""

import json
from pathlib import Path

import stix2

import attack_flow.model  # noqa: F401  (registers the Attack Flow STIX custom objects)
from attack_flow.graph import bundle_to_networkx
from attack_pivot.ingest.afb import CONFIDENCE, ParsedAction, ParsedEdge, ParsedFlow

# Edge types written by bundle_to_networkx for the properties that carry sequence.
SEQUENCE_EDGES = {"effect", "on_true", "on_false"}
ACTION, OPERATOR, CONDITION = "attack-action", "attack-operator", "attack-condition"
ACTOR_TYPES = ("threat-actor", "intrusion-set")


def _confidence(value):
    """Attack Flow STIX confidence is numeric 0-100; tolerate a Builder term."""
    if isinstance(value, int):
        return value
    return CONFIDENCE.get(value)


def _as_text(value):
    return None if value is None else str(value)


def _build_action(node_id, data):
    technique, tactic = data.get("technique_id") or None, data.get("tactic_id") or None
    label = "technique_id" if technique else "tactic_only" if tactic else "none"
    return ParsedAction(
        node_ref=node_id,
        name=data.get("name"),
        technique_id=technique,
        tactic_id=tactic,
        label_source=label,
        confidence=_confidence(data.get("confidence")),
        execution_start=_as_text(data.get("execution_start")),
        execution_end=_as_text(data.get("execution_end")),
    )


def parse_stix(bundle, name=None):
    """
    Parse an Attack Flow STIX bundle.

    The graph comes from :func:`attack_flow.graph.bundle_to_networkx`. Action→action edges are
    induced through operators and conditions, as in ``induce_action_graph``, but keeping ``via``
    from the first pass-through node: ``and`` / ``or`` for operators, ``condition_true`` /
    ``condition_false`` for the ``on_true_refs`` / ``on_false_refs`` branch of a condition.

    :param stix2.Bundle|dict bundle:
    :param str name: Fallback flow name.
    :rtype: ParsedFlow
    """
    if isinstance(bundle, dict):
        bundle = stix2.parse(bundle, allow_custom=True)
    unparsed = [o for o in bundle.objects if isinstance(o, dict)]
    if unparsed:
        raise ValueError(
            f"object could not be parsed into STIX: {unparsed[0].get('id')}"
        )
    graph = bundle_to_networkx(bundle)
    objects = {o["id"]: o for o in bundle.objects}
    flow_obj = next((o for o in bundle.objects if o["type"] == "attack-flow"), None)
    parsed = ParsedFlow(
        name=(flow_obj and flow_obj.get("name")) or name or "unnamed", schema="stix"
    )

    nodes = {n: d for n, d in graph.nodes(data=True) if n in objects}
    parsed.actions = [
        _build_action(n, d) for n, d in nodes.items() if d.get("type") == ACTION
    ]

    def successors(node):
        for _, target, data in graph.out_edges(node, data=True):
            if data.get("type") in SEQUENCE_EDGES and target in nodes:
                yield target, data["type"]

    seen = set()
    for action in parsed.actions:
        stack = [(t, None) for t, _ in successors(action.node_ref)]
        visited = set()
        while stack:
            node, via = stack.pop()
            kind = nodes[node].get("type")
            if kind == ACTION:
                seen.add((action.node_ref, node, via or "direct"))
            elif kind == OPERATOR and (node, via) not in visited:
                v = via or str(nodes[node].get("operator", "AND")).lower()
                visited.add((node, via))
                stack.extend((t, v) for t, _ in successors(node))
            elif kind == CONDITION and (node, via) not in visited:
                visited.add((node, via))
                for t, edge_type in successors(node):
                    branch = (
                        "condition_false"
                        if edge_type == "on_false"
                        else "condition_true"
                    )
                    stack.append((t, via or branch))
    parsed.edges = [ParsedEdge(*e) for e in sorted(seen)]

    _extract_context(parsed, bundle.objects)
    return parsed


def _extract_context(parsed, objects):
    creators = {o.get("created_by_ref") for o in objects}
    for obj in objects:
        kind = obj["type"]
        if kind in ACTOR_TYPES:
            parsed.actors.append(
                {
                    "name": obj["name"],
                    "aliases": list(obj.get("aliases", [])),
                    "type": kind.replace("-", "_"),
                }
            )
        elif kind == "campaign":
            parsed.campaigns.append(obj["name"])
        elif kind == "identity" and obj["id"] not in creators:
            parsed.sectors.extend(obj.get("sectors", []))
        elif kind == "location":
            region = obj.get("country") or obj.get("region") or obj.get("name")
            if region:
                parsed.regions.append(region)
    parsed.sectors = list(dict.fromkeys(parsed.sectors))
    parsed.regions = list(dict.fromkeys(parsed.regions))


def parse_stix_file(path):
    """
    Parse a STIX bundle file, using the file name as the fallback flow name.

    :param Path path:
    :rtype: ParsedFlow
    """
    path = Path(path)
    return parse_stix(json.loads(path.read_text()), name=path.stem)
