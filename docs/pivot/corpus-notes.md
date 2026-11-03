# Corpus notes

Findings about the data that the parser, model and reports depend on. Updated as P0 tasks land.

## P0.5 — seed corpus (41 `.afb`) and the "7 zero-edge flows"

**Result.** The latch → anchor → owner resolution in SPEC §5.1 resolves every `dynamic_line` in all 41
files. None of the 7 flows named in §5.1.6 has zero edges; the parser induces 1,070 action→action
edges over 952 actions (golden counts: `tests/pivot/fixtures/afb_golden.json`; the 1,070 total was
also computed by a separate throwaway script before the parser existed).

**What "0 edges" really meant.** The 7 flows produce zero *technique-labeled* transitions under a
resolver that reads only the `technique_id` property. Their actions keep the technique in the
`ttp` property pair (`[["tactic", "TA…"], ["technique", "T…"]]`), which the Builder's newer
templates write instead. The §5.1.6 hypotheses (anchors attached directly, newer file schema, genuinely
unlinked) were not the cause: all 41 files are schema `attack_flow_v2` and link normally.

| Flow | Actions | Labels |
|---|---|---|
| Turla - Carbon Emulation Plan | 81 | 79 `ttp`, 1 tactic only, 1 none |
| Turla - Snake Emulation Plan | 74 | 74 `ttp` |
| OpenClaw | 18 | 18 `ttp` |
| OpenClaw Command & Control via Prompt Injection | 18 | 18 `ttp` |
| ToolShell Vulnerability in Sharepoint | 15 | 14 `ttp`, 1 tactic only |
| Equifax Breach | 12 | 12 `ttp` |
| Example Attack Tree | 63 | 63 none |

**Parser label order** (`attack_pivot.ingest.afb`): `technique_id` → `ttp.technique` → tactic only
(kept as an action with a tactic, no technique) → unlabeled (kept in the graph structure, excluded from
the technique model). Corpus-wide, of 952 actions: 612 `technique_id`, 215 `ttp`, 52 tactic only,
73 unlabeled. With the `ttp` fallback there are 892 labeled action pairs and 857 unique raw
technique transitions (before ATT&CK-version normalization, which can only merge or drop IDs).

**Non-Enterprise IDs.** 32 actions in the two OpenClaw flows use MITRE ATLAS IDs (`AML.T…`), not
ATT&CK Enterprise. The normalizer will set `technique_id = NULL` for IDs that do not exist in the
pinned Enterprise version and keep `technique_id_original` (SPEC §5.4); they therefore do not enter
the model. Whether to add an ATLAS state space is a product question, not a P0 one.

**Example Attack Tree is not a sequence.** Its 62 edges run from sub-goals to parent goals through
AND/OR nodes (29 leaves with no incoming edge, one sink at the root goal), i.e. goal decomposition,
and its actions carry no technique labels. SPEC §5.1.7 would stamp it `order_basis='explicit'`; the
ingest marks it `unordered` instead (decision logged in `context/decisions.md`). It has no effect on
the technique model today.

**`via`.** Conditions expose `branch:True` / `branch:False` anchors, so true/false is read directly
from the anchor a line leaves, not guessed. Corpus-wide: 610 direct, 216 `and`, 85 `or`, 148
`condition_true`, 5 `condition_false`. No action pair is reachable through two different `via`
values, so edges and action pairs are equal in number.

**Source class.** The two Turla flows are CTID emulation plans, but the seed source "Attack Flow
upstream corpus" is class `independent` (sources.seed.yaml). R1 wants emulation kept as its own
class; revisit when the corpus is ingested (open question in the P0 report).
