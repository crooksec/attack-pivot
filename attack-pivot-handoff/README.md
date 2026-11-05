# ATT&CK-pivot — Handoff Package

Build package for extending MITRE CTID Attack Flow (fork: `crooksec/attack-pivot`) with a probabilistic technique-transition model, a PostgreSQL + Apache AGE knowledge graph, and a blue-team Explorer.

## Contents
| Path | Purpose |
|---|---|
| `CLAUDE.md` | Instructions for Claude Code. **Must sit at the repo root.** |
| `docs/pivot/PRD.md` | Problem, theses, goals, success criteria, risks, phases |
| `docs/pivot/SPEC.md` | Technical design (data model, ingest, model, graph, coverage, pivot, API, CLI, UI, tests) |
| `docs/pivot/TASKS.md` | Ordered build tasks with acceptance criteria |
| `docs/pivot/sources.seed.yaml` | Source registry seed (incl. MITRE CAR, VCDB) |
| `docs/pivot/context/decisions.md` | Decisions made during scoping |
| `docs/pivot/context/assessment-v0.md` | Baseline assessment of the upstream repo and corpus |

## How to use
1. Clone `crooksec/attack-pivot`, then create a branch (e.g. `pivot/p0`).
2. Copy this package's contents into the repo root (it mirrors repo paths).
3. Open Claude Code in the repo: *"Read CLAUDE.md and docs/pivot/, then execute TASKS.md starting at P0.1. Stop at each phase exit for review."*

## Before kickoff
- Confirm the go/no-go thresholds in `PRD.md` §5 (proposed values).
- Corpus targets: proceed at 500 incidents / 5,000 ordered transitions; stretch 2,000 incidents.
