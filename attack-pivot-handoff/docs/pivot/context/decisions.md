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
