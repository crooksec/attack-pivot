# ATT&CK-pivot — Product Requirements Document

**Owner:** Parker Crook · **Status:** Draft v1 · **Date:** 2026-11-02
**Repo:** `crooksec/attack-pivot` (fork of MITRE CTID Attack Flow v4.0) · **License:** Apache 2.0

---

## 1. Problem

Defenders can see which ATT&CK techniques they detect. They can't see **how techniques chain together**. That means they can't answer two questions:

1. **Coverage of the chain.** If an adversary uses technique A, what are they likely to do next (and what did they likely do before)? Would I see any step of that path?
2. **Pivot under constraint.** If I block or harden technique A, where does the adversary most likely go instead, and where should I focus next?

Attack Flow describes individual intrusions as graphs. Each flow is an isolated document, though, and nobody aggregates them into transition statistics. The idea of Markov transitions between techniques was raised publicly at ATT&CKcon 2.0. What blocked it was a lack of data and tooling, not theory.

## 2. Thesis

If enough intrusions are captured as ordered flows, the aggregate gives an empirical transition model P(next technique | current technique). Even a naive first-order model has defensive value.

- **T1 (coverage):** A blue team can overlay its detection coverage (ATT&CK Navigator layer) on the transition model. It can then find the high-probability attack paths it would not observe.
- **T2 (pivot):** A blue team can block techniques in the model and see the most likely alternative transitions and substitutes. This focuses attack-surface-reduction follow-up.

## 3. Goals and non-goals

### Goals (v1)
- G1. Build a persistent **knowledge graph** that holds flows, techniques, actors, campaigns, incidents, sources and coverage. It must be queryable both relationally and as a graph (PostgreSQL + Apache AGE).
- G2. Build a **corpus factory** that turns public threat reporting into ordered Attack Flows with full provenance.
- G3. Build a **global transition model** with smoothing, uncertainty (n and credible interval on every probability) and evaluation against baselines.
- G4. Build a **blue-team Explorer** that supports technique-centric exploration, coverage overlay (T1) and block-and-pivot (T2).
- G5. Store threat actor, campaign, sector, platform, region, source and date metadata on every observation. Actor-conditioned models in v2 then become a query, not a re-ingest.

### Non-goals (v1)
- Actor-, sector- or platform-conditioned probabilities. The data is stored but not modelled.
- Higher-order or contextual sequence models (HMM, n-gram > 1, neural).
- Real-time feeds, multi-tenant auth, SaaS hosting.
- Embedding the Explorer inside the Builder canvas. The Explorer is a separate app to limit fork drift.
- Proprietary or employer data. This is not a PANW project; public sources only.

## 4. Users

| Persona | Need |
|---|---|
| Detection engineer | "What follows T1059.001 most often, and do I detect any of it?" |
| Blue team / ASR lead | "We blocked T1218.011. What do adversaries switch to?" |
| CTI analyst | Build and curate flows; audit the evidence behind any probability |
| Researcher (Parker) | Prove or disprove that transition structure is predictive |

## 5. Success criteria

### Corpus
| Milestone | Distinct incidents | Ordered transitions (incident-level) |
|---|---|---|
| M-Proof (proceed) | **≥ 500** | **≥ 5,000** |
| M-Stretch | **≥ 2,000** | ≥ 20,000 |

"Ordered" means `order_basis ∈ {explicit, timestamp, inferred_narrative}` (see SPEC §5). LLM-only sequencing with no textual support does not count toward the target.

### "Proves it works" (go/no-go at M-Proof). Proposed thresholds; owner to adjust.
1. **Predictive lift.** On a time-based held-out split, the first-order Markov model beats the **popularity baseline** on hit@5 and MRR. The bootstrap 95% CI of the difference must exclude 0.
2. **Calibration.** Expected calibration error ≤ 0.10 over bins with p ≥ 0.05.
3. **Stability.** Leave-one-source-class-out: Spearman ρ ≥ 0.7 on the top-200 transitions.
4. **Ordering quality.** In a human-reviewed sample (≥ 10% of LLM-extracted flows, min 50), ≥ 85% of edges have the correct direction and `order_basis`.

If (1) fails, the result is still publishable as a negative finding. The Explorer then degrades to a co-occurrence tool.

## 6. Functional requirements

### FR-1 Knowledge graph and storage
- PostgreSQL with Apache AGE. Relational tables are the source of truth; the AGE graph is a derived, rebuildable view.
- ATT&CK Enterprise is synced by version, including revoked/deprecated mappings, groups and aliases, software, mitigations and data components.
- Every observation traces back to flow → report → source, with TLP and licence.

### FR-2 Corpus factory
- A source registry (class, publisher, TLP default, licence, reliability A–F).
- Collectors for RSS, sitemaps and bulk repositories. Collectors respect robots.txt and ToS and rate-limit.
- Candidate triage: the report describes an intrusion with ≥ 3 techniques.
- Extraction through the existing AI generation pipeline, extended so every edge carries `order_basis`.
- Incident deduplication: many reports map to one incident, and transitions are counted once per incident.
- A review queue with sampling and metrics.
- Import of existing `.afb` and STIX Attack Flow files, including the 41-flow upstream corpus.
- **Required structured sources:**
  - **MITRE CAR.** Detection analytics mapped to ATT&CK. Feeds the detection side of the graph, a built-in "CAR baseline" coverage layer, and gap → available-analytic annotations in coverage and pivot results.
  - **VERIS Community Database (VCDB).** Incident records mapped to ATT&CK through the CTID VERIS↔ATT&CK mapping. Feeds base rates and context; ordered sequences feed tactic-level transitions. It is also a bias cross-check, because its coding comes from public disclosure rather than vendor telemetry.

### FR-3 Transition model
- Incident-level counting, with START and END pseudo-states.
- Dirichlet smoothing with hierarchical backoff: sub-technique → technique → tactic → uniform.
- Every estimate exposes n, the smoothed p and a 90% credible interval.
- Model runs are versioned and reproducible: parameters, corpus filter and corpus composition are stored.
- An evaluation harness with baselines: uniform, popularity, and co-occurrence (TIE-style).

### FR-4 Explorer
- Technique picker. Forward (next) and backward (previous) distributions at depth 1–3, with a probability threshold.
- Transition matrix heatmap (technique or tactic level). Clicking a cell shows the evidence (incidents, reports, links).
- **Coverage (T1):** import a Navigator layer. Then show covered vs uncovered techniques, the top-k most probable *blind paths*, and P(no detection within H steps) from a start technique or from START.
- **Pivot (T2):** block a set of techniques. Then show renormalized historical alternatives and heuristic substitutes, each clearly labelled by type. Export the focus set as a Navigator layer.
- A corpus composition panel (source class mix, date range, top actors) shown with every view.
- No probability is displayed without its n and interval.

### FR-5 Export
- Navigator layer export (scores = probabilities). CSV of transitions. STIX bundle of TLP:CLEAR flows plus citations.
- **TLP guardrail:** any public export includes only TLP:CLEAR-derived data. Exports from restricted sources fail closed.

## 7. Feedback loops and risks (design must address)

| # | Risk / loop | Mitigation |
|---|---|---|
| R1 | **Detection-survivorship loop.** The corpus contains only detected and reported attacks, so coverage analysis looks best where you already detect. | Track source class; report corpus composition; keep emulation and red-team flows as a separate class; VCDB-vs-rest divergence diagnostic on every model run; document the limitation in the UI |
| R11 | **Coarse mapping contamination.** VERIS→ATT&CK is many-to-many. | `fidelity='mapped_coarse'`; excluded from the technique-level model by default, included at tactic level |
| R2 | **Vendor telemetry bias.** Each vendor sees its own sensor footprint and customer sectors. | Source-class weighting option; leave-one-out stability metric |
| R3 | **Narrative ≠ causal order.** The current extraction prompt chains actions in narrative order without flagging it. | `order_basis` on every edge; prompt change; exclude `unordered` from counts |
| R4 | **Duplicate reporting** inflates counts. | Incident clustering; count once per incident |
| R5 | **ATT&CK version churn.** | Normalize to a pinned version through revoked/deprecated mappings; keep the original ID |
| R6 | **Actor alias chaos.** | Canonicalize to ATT&CK G-IDs plus an alias table; attribution confidence |
| R7 | **Counterfactual pivot error.** Historical alternatives ≠ behaviour under constraint. | Label renormalized output "historical alternative"; separate "substitute (heuristic)"; never merge them into one number |
| R8 | **Adversary adaptation / drift.** | Recency filter on model runs; publish the run date range |
| R9 | **TLP leakage / licensing.** | Fail-closed export filter; store full text locally only; publish derived flows plus citation |
| R10 | **Fork drift from upstream.** | New code in new packages; upstream files touched only where listed in SPEC §11 |

## 8. Phasing

| Phase | Scope | Exit |
|---|---|---|
| P0 Foundation | Postgres+AGE, schema, ATT&CK sync, `.afb`/STIX parser, ingest 41-flow corpus, graph materialization | All 41 flows ingested; zero-edge flows fixed or explained; Cypher successor query works |
| P1 Model + eval | Counting, smoothing, CI, START/END, eval harness, CLI | Eval report runs end-to-end on seed corpus |
| P2 Corpus factory | Source registry, collectors, extraction `order_basis`, dedupe, review queue | **M-Proof: 500 incidents / 5,000 ordered transitions** |
| P3 Validation | Run go/no-go (§5) | Written result |
| P4 Explorer | API + UI: explore, matrix, evidence, coverage, pivot, exports | All FR-4 acceptance tests pass |
| P5 Stretch | 2,000 incidents; actor-conditioned model; pgvector; upstream API → Postgres | Optional |

P4 can start in parallel with P2 once P1 is done (it runs on the seed corpus).

## 9. Open questions
- Q1. Go/no-go thresholds in §5. Proposed values; owner to confirm.
- Q2. Recency window default for model runs (proposal: all data; UI filter by year).
- Q3. Whether to publish the corpus and model as a public dataset (licence review per source).
