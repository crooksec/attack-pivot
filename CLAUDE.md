# CLAUDE.md — attack-pivot

Fork of MITRE CTID Attack Flow (v4.0) extended with **ATT&CK-pivot**: a probabilistic technique-transition model, knowledge graph (PostgreSQL + Apache AGE), and blue-team Explorer.

## Read first
1. `docs/pivot/PRD.md`: what and why, success criteria, risks.
2. `docs/pivot/SPEC.md`: how. Section numbers are referenced everywhere.
3. `docs/pivot/TASKS.md`: build order and acceptance criteria. Work top-down; don't skip exits.
4. `docs/pivot/sources.seed.yaml`: source registry seed.

## Ground rules
- **New code goes in new places:** `src/attack_pivot/`, `src/attack_pivot_explorer/`, `migrations/pivot/`, `tests/pivot/`, `docs/pivot/`. Only touch upstream files listed in SPEC §11, to keep upstream merges clean.
- Relational tables are the source of truth. The AGE graph is derived and must be fully rebuildable (`afp graph sync`).
- Probability math in Python (numpy/scipy sparse), not Cypher.
- Never display or return a probability without `n_ab`, `n_a`, and the credible interval.
- Historical alternatives and functional substitutes (SPEC §8.3) are separate outputs, never combined.
- TLP: public exports and `public=true` API responses include TLP:CLEAR-derived data only; fail closed.
- Never serve or export report full text; `evidence_quote` ≤ 200 chars plus URL.
- Collectors: honour robots.txt and ToS, rate-limit, no paywall or auth bypass. Sources stay `enabled: false` until licence-reviewed.
- Do not change the Attack Flow STIX schema. Edge evidence lives in pivot tables; `.afb` line extras use `x_` properties.
- No employer or proprietary data. Public sources only.

## Tooling
- Python 3.12, Poetry (`poetry install --with api,pivot,dev`), psycopg 3, pytest, black.
- Every AGE connection: `LOAD 'age'; SET search_path = ag_catalog, "$user", public;`.
- Explorer: Vue 3 + Vite + TS + d3 v7 (match the Builder's versions), Pinia, vitest, Playwright.
- Upstream tests must keep passing: `pytest tests/`, and the Builder's tests.

## Definition of done (per task)
Acceptance in TASKS.md met · tests added · `pytest` green · docs updated if behaviour changed · no new upstream files touched outside SPEC §11.
