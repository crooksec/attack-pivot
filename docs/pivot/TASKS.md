# ATT&CK-pivot — Build Tasks

Ordered. Each task: scope → acceptance. § refers to `SPEC.md`. Do not start a phase until the previous phase's exit criteria pass (exception: P4 may start after P1).

## P0 Foundation
- **P0.1 Infra.** `docker-compose.pivot.yml` with `pivot-db` (Apache AGE image, pinned), init SQL, volume; `PIVOT_DATABASE_URL`. → `docker compose -f docker-compose.pivot.yml up` gives a DB where `SELECT * FROM ag_catalog.ag_graph` lists `pivot_graph`. (§3)
- **P0.2 Package skeleton.** `src/attack_pivot/` (db, ingest, normalize, dedupe, model, graph, coverage, pivot, api, cli). Poetry group `pivot`, `afp` entry point. → `afp --help` works; `pytest tests/pivot` runs.
- **P0.3 Migrations.** `migrations/pivot/0001_init.sql` implementing §4. `afp db init|migrate`. → Idempotent; schema test passes.
- **P0.4 ATT&CK sync.** `afp attack sync --version 19.1`. → Techniques, tactics, revoked chains, groups and aliases loaded; revoked-chain unit test.
- **P0.5 `.afb` parser.** §5.1 incl. `via`, context extraction. → Golden edge counts for all 41 corpus files. The 7 zero-edge files are fixed or documented with a reason in `docs/pivot/corpus-notes.md`.
- **P0.6 STIX parser.** §5.2. → `tests/fixtures/*.json` flows ingest.
- **P0.7 Ingest seed corpus.** `afp ingest corpus/*.afb`. → 41 flows, 1 incident each (dedupe of the Conti ×3 / CISA AA22-138B ×3 flows is reviewed manually and recorded).
- **P0.8 CAR sync.** §6.6. → Analytic count matches the repo; CAR baseline Navigator layer generated and loadable in ATT&CK Navigator.
- **P0.9 VCDB sync + mapping.** §6.6. → Records loaded. **Report:** VERIS schema versions present, % of records with an ordered event chain/sequence, mapping coverage %. Decision note on VCDB's transition contribution written to `corpus-notes.md`.
- **P0.10 Graph sync.** §8.1 (structural vertices and edges; `NEXT` arrives in P1). → Cypher: `MATCH (t:Technique {attack_id:'T1059'})<-[:SUBTECHNIQUE_OF]-(s) RETURN count(s)` > 0; `DETECTABLE_BY` edges present.

**Exit P0:** all above green in CI.

## P1 Model + evaluation
- **P1.1 Counting.** §7.1–7.2 (START/END, incident union, level roll-up, `order_basis` filter, `fidelity` filter). → Hand-built fixture tests.
- **P1.2 Smoothing + CI.** §7.3. → Fixture equals hand-computed values to 1e-6; CI matches scipy.
- **P1.3 Model runs.** `afp model build`, `model_run`/`transition_estimate` persistence, corpus_stats snapshot, activate. → Reproducible: same inputs → identical hash of estimates.
- **P1.4 NEXT materialization.** `afp graph sync --run`. → Cypher `MATCH (:Technique {attack_id:'T1566'})-[n:NEXT]->(b) RETURN b.attack_id, n.p ORDER BY n.p DESC` returns rows.
- **P1.5 Eval harness.** §7.4, all baselines, bootstrap, stability, VCDB-vs-rest divergence. → `report.md` generated on the seed corpus (results are expected to be weak at n=41; the pipeline must still run end to end).

**Exit P1:** eval report runs end to end.

## P2 Corpus factory
- **P2.1 Source registry.** `afp sources load` (§6.1); licence/ToS review checklist per source in `docs/pivot/source-review.md`.
- **P2.2 Collectors.** rss, sitemap, github_repo, api, manual (§6.2). → Politeness tests (robots.txt honored, rate limit).
- **P2.3 Triage.** §6.3. → Precision check on a 100-report labelled sample (≥ 0.8).
- **P2.4 Prompt + export change.** §5.3 (upstream touch, §11). → Round-trip test: `order_basis` survives job → `.afb` → Builder open/save → parser.
- **P2.5 Batch extraction.** §6.4 with cost logging.
- **P2.6 Dedupe.** §5.5 with review queue.
- **P2.7 Review queue.** §6.5 (CLI first; Explorer page in P4). → Precision metrics computed.
- **P2.8 Corpus stats.** §6.7.

**Exit P2 (M-Proof):** ≥ 500 incidents, ≥ 5,000 ordered incident-level transitions, review sample meets PRD §5.4. Continue toward M-Stretch (2,000) in the background.

## P3 Validation
- **P3.1** Run eval on the M-Proof corpus; write `docs/pivot/results-mproof.md` with the go/no-go per PRD §5.

## P4 Explorer
- **P4.1 API.** §9 endpoints + schemas + TLP filter. → httpx tests per endpoint; TLP fail-closed test.
- **P4.2 Coverage engine.** §8.2 incl. CAR annotations. → 3-state closed-form test; CAR baseline layer analysis runs.
- **P4.3 Pivot engine.** §8.3. → Renormalization test; substitutes return separate list.
- **P4.4 Explorer app.** §12 views 1–6. → Playwright smoke per view; no probability rendered without n + CI (test).
- **P4.5 Exports.** Navigator layer, CSV, STIX (TLP:CLEAR only).
- **P4.6 Deploy.** nginx `/explorer/`; compose profile.

## P5 Stretch (not scheduled)
2,000 incidents · actor-conditioned model (hierarchical shrinkage to global) · pgvector over report text · move upstream API store to Postgres.
