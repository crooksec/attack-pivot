# ATT&CK-pivot — Assessment v0 (2026-11-02)

## Repo state
- crooksec/attack-pivot = CTID Attack Flow v4.0, synced to upstream 2026-10-27 (ATT&CKcon 7). No divergent commits at time of assessment.
- Components: STIX 2.1 extension (schema 2.0.0: flow/action/asset/condition/operator); Vue/TS Builder (.afb); Python lib/CLI (networkx, graphviz, mermaid, matrix); FastAPI API (LLM extraction PDF/URL/STIX -> canonical flow -> .afb/STIX, SQLite job store, JSON blobs); TIE recommender (WMF, unordered co-occurrence); D3FEND; Atomic Red Team; chat.
- No persistent cross-flow graph. Graph only in-memory per flow. `graph.induce_action_graph` already collapses operators/conditions to action->action edges.
- Edges = bare `effect_refs` lists; no edge properties. `confidence` exists on nodes only.

## Corpus measurement (41 .afb)
- 952 actions, 215 unique techniques, 654 action->action edges, 600 unique transitions, 43 seen >1x.
- 7 flows resolve 0 edges with a naive resolver (attack tree, emulation plans, OpenClaw x2, ToolShell, Equifax) — parser/format check needed (TASKS P0.5).
- threat_actor/campaign objects in ~20/41, inconsistent.

## Conclusions
- Knowledge graph: yes, as a separate store fed by flows. Layers: instance (flows/actions, provenance) / abstraction (technique, tactic, group, campaign, software, D3FEND, detections) / derived (aggregated transition edges with stats).
- Apache AGE: v1.7.0 (Jan 2026, PG18); v1.6 for PG14-17. Probability math in Python (sparse matrices), materialized onto edges. AGE has no GDS-style algorithm library.
- Probabilities belong on aggregate edges, not per-flow edges. Per-flow edges carry evidence: order basis, source, time delta, analyst confidence.
- Binding constraint = corpus size/quality, not graph tech. Needs hierarchical smoothing, credible intervals, incident dedupe, recency, ATT&CK version normalization, alias resolution.
- Bias loop: corpus = detected+reported attacks; coverage analysis built on it overstates coverage where detection already exists.
- Pivot thesis: naive renormalization after blocking a node is a counterfactual error; pair it with substitutability (structural equivalence, TIE similarity, same tactic).
