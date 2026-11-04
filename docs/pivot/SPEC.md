# ATT&CK-pivot — Technical Specification

Companion to `PRD.md`. Written for implementation by Claude Code. Section numbers are stable; tasks in `TASKS.md` reference them.

---

## 1. Baseline (as of upstream 2026-10-27, v4.0)

| Area | Current state | Implication |
|---|---|---|
| Storage | API uses raw `sqlite3` (`src/attack_flow_api/storage/database.py`, `repositories.py` ~1.3k LOC). Flows are stored as JSON blobs in `jobs`. No graph DB, no Neo4j. | New Postgres+AGE store for pivot. Leave the upstream API on SQLite in v1 (R10). |
| Graph | `src/attack_flow/graph.py`: `bundle_to_networkx`, `induce_action_graph` (collapses operators/conditions to action→action). In-memory, per flow. | Reuse the concept; reimplement for `.afb` and keep operator/condition provenance (`via`). |
| Schema | Attack Flow STIX ext 2.0.0. Edges are bare `effect_refs` / `on_true_refs` / `on_false_refs`. `confidence` exists only on nodes. | Do **not** change the flow schema. Edge evidence lives in pivot tables; probabilities live only on aggregate edges. |
| Builder format | `.afb` (`schema: attack_flow_v2`). Objects: nodes with `anchors{angle: anchor_id}`, anchors with `latches[]`, `dynamic_line{source: latch, target: latch}`. | Parser resolves line → latch → anchor → owner node. |
| Corpus | 41 `.afb`, 952 actions, 215 techniques, 654 resolved action edges, 600 unique transitions, 43 seen >1×. 7 flows resolve 0 edges with the naive resolver. | P0 must fix or explain the 7 zero-edge flows. |
| Extraction | `config/ai-prompts.json` rule 4: "When the source order is the only sequencing evidence, connect each action to the next action in that order." | Narrative order is silently encoded as edges. Add `order_basis` (§5.3). |
| Recommender | TIE (WMF over 6,236 reports, **unordered**) in Builder. | Use as a co-occurrence baseline (§7.4) and a substitutability signal (§8.3). |

## 2. Architecture

```
            ┌──────────────── sources.seed.yaml ────────────────┐
collectors ─┤ RSS / sitemap / bulk repo / manual URL list       │
            └──────┬────────────────────────────────────────────┘
                   ▼
         pivot.report (raw text local, sha256, TLP, licence)
                   ▼  triage (≥3 techniques, intrusion narrative)
   existing attack_flow_api jobs (LLM extraction) ──► .afb / STIX
                   ▼
   parser ──► pivot.flow / action_obs / transition_obs (+order_basis, via)
                   ▼
   normalize (ATT&CK version, aliases) ─► dedupe (incident clustering)
                   ▼
   model build (counts → smoothed P, CI) ─► model_run / transition_estimate
                   ▼                                  ▼
   AGE graph materialize (NEXT edges)        eval harness
                   ▼
   FastAPI /api/v1/pivot/*  ◄──  Explorer (Vue 3 + d3)
```

**New code locations**
- `src/attack_pivot/`: Python package (DB, ingest, model, graph, coverage, pivot, API router, CLI).
- `src/attack_pivot_explorer/`: standalone Vue 3 + Vite + TS + d3 app.
- `migrations/pivot/`: numbered SQL migrations.
- `docs/pivot/`: these documents.

## 3. Infrastructure

- `docker-compose.pivot.yml` adds:
  - `pivot-db`: image `apache/age` (pin a tag supporting PG 16 or 17 with AGE ≥ 1.6; verify the current tag at build time; AGE 1.7.0 targets PG 18). Persistent volume. Init script runs `CREATE EXTENSION age; LOAD 'age'; SET search_path = ag_catalog, "$user", public;` and `SELECT create_graph('pivot_graph');` (the graph is not named `pivot`: AGE keeps a graph's tables in a schema of the same name, which would collide with the relational schema `pivot`).
  - `attack-flow-api`: gains env `PIVOT_DATABASE_URL`. The pivot router mounts only if this is set.
  - `pivot-explorer`: static build served by the existing nginx proxy at `/explorer/`.
- Python deps (new poetry group `pivot`): `psycopg[binary]>=3.2`, `numpy`, `scipy`, `pyyaml`, `feedparser`, `httpx`, `rapidfuzz`. Use the existing `networkx`.
- Every AGE session must run `LOAD 'age'` and set `search_path` (connection hook).

## 4. Data model (relational, source of truth)

Schema `pivot`. All tables carry `created_at timestamptz default now()`.

```sql
-- provenance
source(id uuid pk, name text unique, publisher text,
       source_class text check in ('government','vendor','isac','independent','emulation','academic','community','structured_dataset','detection_repo','other'),
       base_url text, collector text, collector_config jsonb,
       default_tlp text check in ('clear','green','amber','amber+strict','red'),
       licence text, reliability char(1) check in ('A','B','C','D','E','F'), notes text)

report(id uuid pk, source_id fk, url text, title text, published_at date, retrieved_at timestamptz,
       sha256 text unique, tlp text, credibility smallint check 1..6,
       text_path text,               -- local file, never exported
       api_input_source_id text,     -- FK-by-value to attack_flow_api input_sources
       triage_status text check in ('new','candidate','rejected','extracted','failed'),
       triage_reason text, technique_mentions int)

incident(id uuid pk, label text, first_seen date, last_seen date,
         cluster_method text, cluster_confidence real)
report_incident(report_id fk, incident_id fk, link_confidence real, method text, pk(report_id, incident_id))

-- flows and observations
flow(id uuid pk, report_id fk null, incident_id fk null, name text,
     origin text check in ('upstream_corpus','manual','llm','stix_import'),
     llm_provider text, llm_model text, api_job_id text,
     attack_version text, afb jsonb, stix jsonb,
     review_status text check in ('unreviewed','accepted','corrected','rejected'),
     reviewer text, reviewed_at timestamptz, tlp text)

action_obs(id uuid pk, flow_id fk, node_ref text,          -- afb instance id / STIX id
           technique_id text, technique_id_original text,  -- normalized vs as-extracted
           tactic_id text, name text, confidence smallint,
           execution_start timestamptz, execution_end timestamptz)

transition_obs(id uuid pk, flow_id fk, incident_id fk null,
               src_action fk action_obs, dst_action fk action_obs,
               src_technique text, dst_technique text,     -- normalized
               order_basis text check in ('explicit','timestamp','inferred_narrative','mapped_sequence','inferred_llm','unordered'),
               fidelity text check in ('technique','mapped_coarse') default 'technique', -- mapped_coarse = derived via VERIS→ATT&CK mapping
               via text check in ('direct','and','or','condition_true','condition_false'),
               delta_seconds bigint null, evidence_quote text null)

-- context (stored now, modelled in v2)
actor(id uuid pk, attack_group_id text unique null, name text)
actor_alias(actor_id fk, alias text, source text, pk(actor_id, alias))
flow_actor(flow_id fk, actor_id fk, attribution_confidence real, basis text)
flow_context(flow_id pk fk, sectors text[], platforms text[], regions text[],
             victim_org_size text null, initial_access_vector text null)

-- ATT&CK reference (versioned)
attack_version(version text pk, released date, stix_url text, synced_at timestamptz)
technique(attack_id text, version text, name text, parent_id text null, tactic_ids text[],
          platforms text[], revoked bool, deprecated bool, stix_id text, pk(attack_id, version))
technique_replacement(from_id text, to_id text, version text, relation text) -- revoked-by
tactic(attack_id text, version text, name text, shortname text, ord smallint, pk(attack_id, version))

-- model
model_run(id uuid pk, label text, attack_version text, params jsonb, corpus_filter jsonb,
          corpus_stats jsonb, eval jsonb null, is_active bool default false)
transition_estimate(run_id fk, level text check in ('subtechnique','technique','tactic'),
                    src text, dst text, n_ab int, n_a int, p_mle real, p real,
                    ci_low real, ci_high real, pk(run_id, level, src, dst))

-- detection analytics (MITRE CAR; extensible to Sigma etc.)
analytic(id text pk,               -- e.g. CAR-2020-09-001
         repo text default 'car', title text, information_domain text,
         platforms text[], data_model_refs text[], url text, raw jsonb, synced_at timestamptz)
analytic_technique(analytic_id fk, technique_id text, tactic_id text null,
                   coverage text null,  -- as declared by CAR (e.g. Low/Moderate/High) if present
                   pk(analytic_id, technique_id))

-- VERIS / VCDB (raw records kept; mapped into flow/action/transition tables)
veris_incident(id text pk,          -- VCDB incident_id
               veris_version text, raw jsonb, year smallint,
               victim_industry text, victim_size text, actor_types text[],
               has_sequence bool, flow_id fk null, imported_at timestamptz)
veris_attack_map(veris_path text, technique_id text, map_version text,
                 relation text, pk(veris_path, technique_id, map_version))
                 -- from center-for-threat-informed-defense/attack_to_veris

-- coverage
coverage_layer(id uuid pk, name text, navigator jsonb, attack_version text, imported_at timestamptz)
coverage_item(layer_id fk, technique_id text, score real null, covered bool, pk(layer_id, technique_id))
```

Indexes: `transition_obs(src_technique, dst_technique)`, `transition_obs(incident_id)`, `transition_estimate(run_id, level, src)`, `report(sha256)`, `flow(incident_id)`.

## 5. Ingest

### 5.1 `.afb` parser (`attack_pivot.ingest.afb`)
1. Index objects by `instance`. Build `anchor → owner` from each node's `anchors` map, then `latch → owner` from each anchor's `latches`.
2. For each `dynamic_line`: `src_owner = owner(latch(source))`, `dst_owner = owner(latch(target))`.
3. Node types for the action graph: `action`. Pass-through types: `AND_operator`, `OR_operator`, `condition`. Everything else (assets, tools, malware, threat_actor, campaign …) is context, not sequence.
4. Induce action→action edges by DFS through pass-through nodes, recording `via` from the first pass-through node encountered (condition: `on_true` vs `on_false` per latch side if determinable, else `condition_true`).
5. Extract `threat_actor`, `intrusion_set`, `campaign`, `identity` (sector), `location` objects into `flow_actor` / `flow_context`.
6. **Must** fix or document why these resolve 0 edges with the naive resolver: `Example Attack Tree`, `Turla - Carbon Emulation Plan`, `Turla - Snake Emulation Plan`, `OpenClaw`, `OpenClaw Command & Control via Prompt Injection`, `ToolShell Vulnerability in Sharepoint`, `Equifax Breach`. Likely causes: lines attached via anchors directly, a newer file schema, or genuinely unlinked flows. Add a regression test per file.
7. Upstream corpus flows get `origin='upstream_corpus'`, `order_basis='explicit'` (analyst-authored), `review_status='accepted'`.

### 5.2 STIX parser
Use `attack_flow.graph.bundle_to_networkx` + `induce_action_graph`, extended to preserve `via`. `order_basis='explicit'` unless the bundle has the pivot extension property (§5.3).

### 5.3 Extraction prompt change (upstream file touch, §11)
- Replace rule 4 in `config/ai-prompts.json`. The LLM must emit, per action link, `order_basis` (`explicit` | `timestamp` | `inferred_narrative` | `unordered`) and a ≤ 200-char `evidence_quote`.
- Rule text: *"Link actions only where the source states or clearly implies sequence. Label each link with order_basis. If techniques are listed without sequence (e.g., a technique table), do not link them; return them unlinked."*
- Carry these through the canonical flow → `.afb` export as a line property `x_order_basis` / `x_evidence_quote`. The Builder ignores unknown props; verify round-trip in a test.
- Edges from LLM output that lack the field get `inferred_llm`.

### 5.4 Normalization
- `attack sync --version X`: pull Enterprise STIX from `mitre-attack/attack-stix-data` for the version and populate `technique`, `tactic`, `technique_replacement`, groups → `actor` + `actor_alias`.
- Normalize `technique_id` to the active model's ATT&CK version through `technique_replacement` chains. Keep `technique_id_original`. If an ID is unmappable, set `technique_id = NULL` and log it.
- Normalize actor names through alias table → G-ID (exact, then `rapidfuzz` ≥ 92 with a manual-confirm queue).

### 5.5 Incident deduplication (`attack_pivot.dedupe`)
- Candidate pairs: same actor (or both unknown) AND date windows within 45 days AND (shared victim/sector string OR Jaccard(technique sets) ≥ 0.5 OR shared URL citations).
- Score = weighted sum; ≥ 0.75 auto-link, 0.5–0.75 goes to the review queue, < 0.5 creates a new incident.
- Every flow belongs to exactly one incident; a singleton incident is created if needed.
- **Counting rule:** a transition (a, b) contributes **at most 1 per incident** (union across that incident's flows).

## 6. Corpus factory

### 6.1 Source registry
`docs/pivot/sources.seed.yaml` is loaded by `afp sources load`. Each entry has: `name, publisher, source_class, base_url, collector (rss|sitemap|github_repo|api|manual), collector_config, default_tlp, licence, reliability, notes`. Licence and ToS are checked per source before enabling (`enabled: false` by default for any source not yet reviewed).

### 6.2 Collectors
- Collectors respect robots.txt, use a per-domain rate limit (default 1 req / 5 s) and a descriptive user agent. They don't bypass paywalls or authentication. ISAC/member portals are `collector: manual` only, ingesting files the owner already has access to, with TLP set from the document.
- Store raw text locally at `DATA_DIR/pivot/reports/<sha256>.txt`. Dedupe by sha256 and canonical URL.

### 6.3 Triage
- A cheap first pass: regex for ATT&CK IDs plus keyword heuristics. Then an LLM classification (`is_intrusion_narrative`, `technique_count_estimate`, `has_sequence_language`).
- Candidate = intrusion narrative AND ≥ 3 techniques. Store the reason.

### 6.4 Extraction
- Submit candidates to the existing API job pipeline (`POST /api/v1/jobs`). Poll, then import the resulting `.afb` through §5.1. Link `flow.api_job_id`, `flow.report_id`.
- Batch runner with concurrency limit and cost logging (provider/model/tokens from job audit).

### 6.5 Review queue
- CLI + minimal Explorer page that lists flows with edges, `order_basis` and `evidence_quote`. Reviewer actions: accept / correct (flip, delete, add edge, change basis) / reject.
- Sampling: stratified by source_class; min(10%, 50) per batch. Report edge-direction precision and `order_basis` accuracy (PRD §5.4).

### 6.6 Structured datasets (required sources)

These two have no narrative text, so they bypass the LLM extraction path (§6.3–6.4).

**MITRE CAR** (`github.com/mitre-attack/car`, Apache-2.0, YAML in `analytics/`)
- **Role: detection side, not transition data.** CAR analytics are detections mapped to ATT&CK. They contribute no transitions.
- `afp car sync`: clone or pull the repo, parse each analytic YAML into `analytic` + `analytic_technique` (fields: id, title, information_domain, platforms, data model refs, ATT&CK coverage entries incl. sub-techniques/tactics and coverage level where declared). Verify field names against the current YAML at build time.
- Uses:
  1. KG edges `Technique -[:DETECTABLE_BY]-> Analytic`.
  2. Generate a **"CAR baseline" Navigator layer** (technique covered if ≥ 1 analytic) as a built-in reference coverage profile.
  3. In coverage analysis (§8.2), annotate every blind path node and every gain-ranking row with the CAR analytics that exist for it. A gap then comes with a ready-made analytic where one exists.
  4. Pivot output (§8.3) lists available analytics for each alternative or substitute.

**VERIS Community Database** (`github.com/vz-risk/VCDB`, JSON per incident, VERIS schema)
- **Role: incident base rates, context, and a differently-biased cross-check.** VCDB is coded mostly from public breach disclosures and news, not vendor telemetry. That makes it the main counterweight for R1/R2.
- `afp vcdb sync`: clone or pull, load `data/json/validated/*.json` into `veris_incident` (raw JSON plus extracted industry, size, actor types, year).
- ATT&CK mapping: load the CTID VERIS↔ATT&CK mapping (`center-for-threat-informed-defense/attack_to_veris`; Mappings Explorer) into `veris_attack_map`. VERIS action varieties map many-to-many and coarsely to techniques. Every derived action gets `fidelity='mapped_coarse'`, and a VERIS item that maps to k techniques yields k candidate actions at weight 1/k.
- **Sequences:** determine in P0 whether the VCDB records carry an ordered event chain (VERIS `plus.event_chain` or a newer sequence field, depending on schema version) and what fraction populate it. Only records with an ordered chain produce `transition_obs` (`order_basis='mapped_sequence'`). Records without one contribute context, co-occurrence and base rates only.
- Modelling defaults: `mapped_coarse` transitions are **excluded from the technique-level model** and **included at tactic level**. Every model run reports a VCDB-vs-rest comparison (tactic-level transition divergence, JS distance) as a bias diagnostic. Each VCDB incident is its own `incident`. Cross-dedupe against narrative reports uses victim, date and industry (§5.5).
- Count toward the corpus targets only the VCDB incidents with ordered sequences; report them as a separate line in `afp corpus stats`.

### 6.7 Corpus metrics (`afp corpus stats`)
Incidents, flows, reports by source_class/TLP/year; ordered transitions by order_basis; unique techniques; transitions with n ≥ 2, 5, 10; top actors; review precision. Progress is tracked against M-Proof (500/5,000) and M-Stretch (2,000/20,000).

## 7. Transition model (`attack_pivot.model`)

### 7.1 States
Technique states at the chosen `level`, plus `START` and `END`.
- For each flow's action graph: nodes with in-degree 0 receive `START → a`; nodes with out-degree 0 receive `b → END`.
- At `level='technique'`, sub-techniques roll up to their parent. At `level='tactic'`, techniques map to their tactic. Multi-tactic techniques use the flow's `tactic_id` if present, else split weight 1/k.

### 7.2 Counts
`n_ab` = number of distinct incidents containing transition a→b (with `order_basis ∈ run.params.allowed_bases`, default `explicit, timestamp, inferred_narrative`). `n_a = Σ_b n_ab`. Self-loops are kept but flagged (`params.self_loops: keep|drop`, default keep).

### 7.3 Smoothing with hierarchical backoff
```
p(b|a) = (n_ab + α · q(b|a)) / (n_a + α)
q(b|a) = backoff prior: p_parent(parent(b)|parent(a)) · share(b | parent(b))
         → tactic-level → empirical marginal of b (popularity) → uniform
```
- `α` default 1.0 (param). `share(b|parent(b))` = marginal frequency of b among siblings.
- Credible interval: the marginal of the Dirichlet posterior is `Beta(n_ab + α q, n_a − n_ab + α(1 − q))`. Report the 5th and 95th percentiles (`scipy.stats.beta.ppf`).
- `n_a = 0` → p = q, flagged `no_data`.
- Store all (a, b) with `n_ab > 0` plus the top-20 prior-only successors per a (UI marks them "prior").

### 7.4 Evaluation (`afp model eval`)
- **Split:** time-based by `incident.first_seen` (train ≤ cutoff, test > cutoff; default cutoff = 80th percentile date). Also 5-fold incident-grouped CV.
- **Task:** for each test transition a→b (a ≠ START), rank candidates b′ by model score.
- **Metrics:** hit@1/5/10, MRR, mean log-likelihood, Brier, ECE (10 bins), reliability diagram (PNG + JSON).
- **Baselines:**
  - uniform;
  - popularity (marginal of b);
  - co-occurrence (P(b ∈ incident | a ∈ incident), TIE-style, unordered);
  - tactic-order prior (b's tactic follows a's in kill-chain order).
- **Significance:** paired bootstrap (1,000×) over test incidents; report 95% CI of the metric difference vs each baseline.
- **Stability:** leave-one-source_class-out; Spearman ρ on the top-200 transitions vs the full model.
- Output: `model_run.eval` JSON plus `DATA_DIR/pivot/eval/<run_id>/report.md`.

## 8. Graph, coverage and pivot

### 8.1 AGE graph (`attack_pivot.graph`)
Rebuildable from relational tables (`afp graph sync [--run RUN]`).

| Vertex label | Key props |
|---|---|
| `Technique` | attack_id, name, parent_id, tactics |
| `Tactic` | attack_id, name, ord |
| `Group` | attack_group_id, name |
| `Incident` | id, label, first_seen |
| `Flow` | id, name, origin, tlp |
| `Report` | id, url, published_at, tlp |
| `Source` | id, name, source_class, reliability |
| `Software`, `Mitigation`, `DataComponent`, `D3FEND` | attack/d3fend ids |
| `Analytic` | id (CAR-xxxx), title, information_domain |
| `VerisIncident` | id, industry, year |
| `State` | `START`, `END` |

| Edge label | From → To | Props |
|---|---|---|
| `NEXT` | Technique/State → Technique/State | run_id, level, p, ci_low, ci_high, n_ab, n_a |
| `SUBTECHNIQUE_OF` | Technique → Technique | |
| `IN_TACTIC` | Technique → Tactic | |
| `OBSERVED` | Flow → Technique | count |
| `PART_OF` | Flow → Incident | |
| `REPORTED_IN` | Flow → Report | |
| `PUBLISHED_BY` | Report → Source | |
| `ATTRIBUTED_TO` | Incident → Group | confidence |
| `USES` | Group → Technique | from ATT&CK |
| `MITIGATED_BY`, `DETECTED_BY`, `COUNTERED_BY` | Technique → Mitigation / DataComponent / D3FEND | |
| `DETECTABLE_BY` | Technique → Analytic (CAR) | coverage |
| `CODED_AS` | Incident → VerisIncident | |

Only the active run's `NEXT` edges are materialized by default. Probability math runs in Python on scipy sparse matrices loaded from `transition_estimate`, not in Cypher. Cypher handles traversal and joins (e.g. groups using reachable techniques).

### 8.2 Coverage (T1, `attack_pivot.coverage`)
- Import a Navigator layer (v4.x JSON). A technique is `covered` if `enabled != false` and (`score ≥ threshold` (param, default > 0) or `color` set when no score). Sub-technique coverage does not imply parent coverage; parent coverage applies to sub-techniques only if `params.parent_implies_children` (default false).
- Transition matrix **P** (rows sum to 1, includes END). Let **U** = uncovered states.
- **P(no detection within H steps | start s)** = Σ over paths of length ≤ H staying in U (paths that reach END before H count as undetected-complete). Computed with the restricted matrix `P_U` via iteration (H ≤ 10).
- **Blind paths:** beam search (width 200) from s over −log p, keeping top-k (default 20) paths of length ≤ H where every node ∈ U. Also list "single-point" paths (exactly one covered node), the fragile coverage.
- **Coverage gain ranking:** for each uncovered technique t, Δ = reduction in P(no detection within H | START) if t becomes covered. This gives a ranked "add detection here next" list.

### 8.3 Pivot (T2, `attack_pivot.pivot`)
Input: blocked set B, optional context technique(s) A (predecessors of interest; default = all predecessors of B).

Two outputs, never merged into one number:
1. **Historical alternatives.** For each a ∈ A: `p′(b|a) = p(b|a) / (1 − Σ_{x∈B} p(x|a))`, b ∉ B. Labelled *"what else followed a historically."*
2. **Functional substitutes (heuristic).** For each x ∈ B, score y ∉ B:
   `s(x,y) = w1·cos(in_x, in_y) + w2·cos(out_x, out_y) + w3·[same tactic] + w4·[same parent] + w5·cos_TIE(x,y)`,
   where in/out are columns/rows of P. Defaults w = (0.3, 0.3, 0.15, 0.15, 0.1); TIE is optional if the model is loadable server-side, else w5 = 0 and the rest is renormalized. Labelled *"techniques that play a similar role."*
- **Focus set export:** union of top-N from both lists, with scores, as a Navigator layer.

## 9. API (`/api/v1/pivot`, mounted only when `PIVOT_DATABASE_URL` is set)

| Method | Path | Purpose |
|---|---|---|
| GET | `/techniques?q=&level=` | search |
| GET | `/runs` · POST `/runs` · POST `/runs/{id}/activate` | model runs |
| GET | `/runs/{id}/eval` | eval report |
| GET | `/next/{technique}?depth=1..3&min_p=&run=` | forward distribution (k-step via Pᵏ; per-step tree for Sankey) |
| GET | `/prev/{technique}?depth=&min_p=&run=` | backward (Bayes inversion using stationary-free empirical in-counts) |
| GET | `/matrix?level=technique\|tactic&run=&min_n=` | heatmap data |
| GET | `/evidence?src=&dst=` | incidents, flows, reports, order_basis, quotes (TLP-filtered) |
| POST | `/coverage/layers` · GET `/coverage/layers` | Navigator import |
| POST | `/coverage/analyze` | `{layer_id, start, horizon, k}` → P(no-detect), blind paths, gain ranking |
| POST | `/pivot` | `{blocked[], context[], n}` → alternatives, substitutes |
| POST | `/export/navigator` | layer from any result set |
| GET | `/corpus/stats` | composition |
| POST | `/sources/load` · POST `/reports/ingest` · GET `/review/queue` · POST `/review/{flow_id}` | corpus ops |

Every response carrying probabilities includes `run_id`, `n_ab`, `n_a`, `ci_low`, `ci_high` and `corpus_stats_ref`. Pydantic models live in `attack_pivot/api/schemas.py`.

## 10. CLI (`afp`)
```
afp db init | migrate
afp attack sync --version 19.1
afp sources load docs/pivot/sources.seed.yaml
afp car sync                      # MITRE CAR analytics → analytic tables + CAR baseline layer
afp vcdb sync [--map-version V]   # VCDB + CTID VERIS↔ATT&CK mapping
afp collect [--source NAME] [--since DATE]
afp triage [--limit N]
afp extract [--limit N] [--provider P --model M] [--concurrency 4]
afp ingest corpus/*.afb | path/to/*.json
afp dedupe [--auto-only]
afp review sample --batch BATCH
afp corpus stats
afp model build --level technique --alpha 1 [--bases explicit,timestamp,inferred_narrative] [--label L]
afp model eval RUN
afp graph sync [--run RUN]
afp coverage analyze --layer layer.json --start START --horizon 5
afp pivot --block T1218.011,T1059.001
afp export navigator --run RUN --from T1566.001 --depth 2 -o out.json
```

## 11. Upstream files touched (keep to this list)
- `config/ai-prompts.json`: rule 4 replacement + `order_basis` / `evidence_quote` output fields (§5.3).
- Canonical flow / `.afb` export services in `src/attack_flow_api/services/` that carry link properties: pass through `x_order_basis`, `x_evidence_quote`.
- `src/attack_flow_builder/src/assets/configuration/AttackFlowTemplates/BaseObjects.ts`: `x_order_basis` / `x_evidence_quote` string properties on `dynamic_line`, so the Builder keeps them on open/save (added in P2.4; the Builder drops properties its template does not define).
- `src/attack_flow_api/main.py`: conditional router mount.
- `pyproject.toml`: `pivot` group, `afp` script, package include.
- `deploy/nginx/*.conf`: `/explorer/` location.
- `README.md`: one-line pointer to `docs/pivot/`.

## 12. Explorer (`src/attack_pivot_explorer/`)
Vue 3 + Vite + TS + d3 v7 (matches Builder versions). Pinia store. API base from `VITE_API_BASE_URL`.

Views:
1. **Explore.** Technique picker; direction toggle; depth 1–3; min p; Sankey of the k-step tree. Each link is labelled with p, an [ci] bar and n. A "prior" style is used where n_ab = 0.
2. **Matrix.** Tactic-ordered heatmap with log color scale; min-n filter. Cell click opens an evidence drawer.
3. **Coverage.** Upload a layer; select start (default START); horizon. Shows a P(no detection) gauge, a blind-path list (click to highlight in Sankey), a fragile-path list and a gain ranking table. Export Navigator.
4. **Pivot.** Multi-select blocked techniques. Two clearly separated panels (historical alternatives / functional substitutes) with legends explaining the difference. Export focus layer.
5. **Corpus.** Composition charts, model run selector, eval summary, review queue (P2).
6. **Persistent banner** with the run label, corpus size, date range and a limitations link (R1/R2/R7).

## 13. Testing
- Unit tests:
  - parser (all 41 corpus files; golden edge counts per file);
  - normalization (revoked chain);
  - counting rule (incident union);
  - smoothing (hand-computed fixtures);
  - CI (scipy reference);
  - coverage (3-state chain closed-form);
  - pivot renormalization;
  - TLP export filter (fails closed).
- Integration: docker-compose with `pivot-db`; `afp ingest corpus/*.afb && afp model build && afp graph sync`. A Cypher query for `NEXT` from T1566.001 returns ≥ 1 edge.
- API tests with httpx against a seeded DB.
- Explorer: vitest for stores, Playwright smoke for each view.
- CI: extend `.github/workflows/build.yml` with a pivot job (service container for AGE).

## 14. Security and compliance
- No credentials in repo. Provider keys stay as in the upstream `.env`.
- Report full text is never served by the API (only `evidence_quote` ≤ 200 chars and URL).
- TLP filter is applied at the query layer for any `public=true` request and on all exports; the default for exports is `public=true`.
- ATT&CK Terms of Use attribution in the Explorer footer and README.
