# ATT&CK-pivot — Decisions log

## 2026-11-02
- Not a PANW project. Open/personal; no Unit 42 internal data. Public sources only (Unit 42 public blog OK as OSINT).
- Coverage input: ATT&CK Navigator layers.
- Probability scope v1: global transition probabilities (Markov, naive first-order acceptable as baseline). Prove on large corpus.
- Still store threat actor, campaign, sector, platform, source, date metadata on every flow/edge observation so actor-conditioned models are a later query, not a re-ingest.
- Storage: Attack Flow has no graph DB (no Neo4j). API uses raw `sqlite3` (storage/database.py + storage/repositories.py, JSON-blob columns); Builder is browser-only; graphs are in-memory networkx. Decision: PostgreSQL + Apache AGE for pivot. Upstream API stays on SQLite in v1 (fork drift), migrate in P5.
- Prior art not a priority; the Markov-chain idea was presented publicly at ATT&CKcon 2.0.
- Sources: open-ended — gov, vendor TI, ISACs, other OSINT. Registry with class/TLP/licence/reliability; incident-level dedupe; TLP:CLEAR-only public exports.
- Required structured sources: MITRE CAR (detection side: DETECTABLE_BY edges, CAR baseline layer, gap→analytic annotations) and VERIS Community Database (via CTID attack_to_veris mapping; mapped_coarse fidelity; tactic-level transitions only where ordered sequence exists; bias cross-check).
- Corpus targets: proceed at 500 incidents / 5,000 ordered transitions (M-Proof); stretch 2,000 incidents.
- Finding: upstream extraction prompt rule 4 chains actions in narrative order without flagging → add order_basis per edge.
- Open: go/no-go thresholds in PRD §5 are proposals pending owner confirmation.

## 2026-11-03 (build kickoff, P0)
- Branch `pivot/p0`. Handoff docs and `docs/pivot/context/` imported in an initial commit (the handoff zip and stray `zijOeyo2` zip are not committed).
- ATT&CK version: default to **20.0** (`enterprise-attack-20.0.json` exists, released 2026-10-13), overriding the 19.1 in TASKS P0.4. Inspect v19/v20 structure at sync time before assuming normalization rules.
- Python: **3.15** (host has 3.12 and 3.15.0). Upstream caps `python = ">=3.12,<3.15"`; widen to `<3.16` in `pyproject.toml`. Fall back to 3.14 if numpy/scipy/psycopg wheels are not available for 3.15.
- `poetry.lock` deleted and regenerated against newer dependencies. Pivot group uses current versions. Bumps to shared groups (networkx, jsonschema, pytest, black) are made only where `pytest tests/` stays green, each logged here.
- AGE image pinned to `apache/age:release_PG17_1.7.0` (PG 17, AGE 1.7.0; within SPEC §3 range). Digest recorded at P0.1.
- No host `psql`. DB access is psycopg 3 from Python; ad-hoc SQL via `docker compose exec` into the container.
- Corpus finding (P0.5 input): `.afb` line/anchor/latch resolution works on all 41 files. The 7 "zero-edge" flows are zero **technique-labeled** transitions: actions carry the technique only in the `ttp` property pair, not `technique_id`. Of 952 actions: 612 `technique_id`, 215 `ttp` technique only, 52 tactic only, 73 no label. Parser label order: `technique_id` → `ttp.technique` → tactic-only (tactic-level) → unlabeled (structure only, excluded from technique model). Example Attack Tree has no labels; edge semantics (sequence vs goal decomposition) to be checked in P0.5 before assigning `order_basis`.
- AGE image digest (P0.1): `apache/age@sha256:92a5d223965bc2e436f9eee436e0bd2c0d81f3b59124b3d197ec94706f3450a8` (`release_PG17_1.7.0`; PG 17.11, AGE 1.7.0 verified). Host port defaults to 127.0.0.1:5433; local credentials live in `.env.pivot` (excluded via `.git/info/exclude`, not `.gitignore`, to avoid touching an upstream file).
- Dependency upgrades (P0.2), env = Python 3.15.0, Poetry 2.5.1 installed in `~/.local/share/pypoetry-venv` (venv at `./.venv`, in-project via untracked `poetry.toml`). Wheels for numpy 2.5, scipy 1.18, psycopg 3.3 all exist for 3.15. `poetry.lock` regenerated from scratch.
  - Upgraded: networkx 2.8 → 3.7, pytest 7 → 9, pytest-cov 6 → 7, pytest-mock 3.5 → 3.17, black 22 → 25.12 (22.x crashes on Python ≥3.14 with `ast.Str`). Upstream suite: 551 passed, 1 skipped (the skip is the new DB test with no `PIVOT_DATABASE_URL`).
  - Removed: `pytest-flake8` (dev dep, never invoked anywhere in the repo, abandoned, fails to load under pytest 9).
  - Held back: `jsonschema` stays at 4.17.3. `src/attack_flow/schema.py` uses `jsonschema.validators.RefResolver`, which 4.18+ breaks (8 upstream schema tests fail on 4.26). Fixing means rewriting an upstream file outside SPEC §11; deferred.
  - Held back: `black` capped `<26`. Black 26 reformats upstream `src/attack_flow/{docs,matrix,graphviz}.py` and would fail the existing CI `black --check src/attack_flow/`.
- **AGE graph/schema name collision (P0.3).** SPEC §3 names the AGE graph `pivot` and §4 names the relational schema `pivot`; AGE stores graph tables in a Postgres schema of the graph's name, so they are the same namespace. Verified in a scratch DB: `drop_graph('pivot', true)` cascade-drops every relational table, and `create_graph('pivot')` fails if the schema already exists. Kept the SPEC names (no deviation). Mitigations: (a) `afp db init` creates the graph *before* the schema/ledger; (b) `afp graph sync` rebuilds by deleting vertices/edges, never `drop_graph` (a test greps the source and migrations for `drop_graph`); (c) warning at the top of `0001_init.sql`. Alternative if you prefer isolation: rename the graph to `pivot_graph` (touches SPEC §3/§8, TASKS P0.1 acceptance wording). Raised in the P0 report.
- Additive schema choices in `0001_init.sql` beyond SPEC §4 (none remove or rename anything): `source.enabled boolean default false` (SPEC §6.1 and the seed YAML need it); `pivot.schema_migration` ledger with checksums; PK on `technique_replacement(from_id,to_id,version,relation)`; `UNIQUE(flow_id,node_ref)` on `action_obs`; partial unique index allowing one active `model_run`; `CHECK` on `evidence_quote` ≤ 200 chars (CLAUDE.md rule); CHECKs on TLP values for `report.tlp`/`flow.tlp`.
