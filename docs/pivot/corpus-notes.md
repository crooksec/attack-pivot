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
| OpenClaw | 18 | 18 `ttp` (all ATLAS IDs) |
| OpenClaw Command & Control via Prompt Injection | 18 | 18 `ttp` (all ATLAS IDs) |
| ToolShell Vulnerability in Sharepoint | 15 | 14 `ttp`, 1 tactic only |
| Equifax Breach | 12 | 12 `ttp` |
| Example Attack Tree | 63 | 63 none |

**Parser label order** (`attack_pivot.ingest.afb`): `technique_id` → `ttp.technique` → tactic only
(kept as an action with a tactic, no technique) → unlabeled (kept in the graph structure, excluded from
the technique model). Corpus-wide, of 952 actions: 612 `technique_id`, 215 `ttp`, 52 tactic only,
73 unlabeled. With the `ttp` fallback there are 892 labeled action pairs and 857 unique raw
technique transitions (before ATT&CK-version normalization, which can only merge or drop IDs).

**Non-Enterprise IDs — the two OpenClaw flows are ATLAS, not ATT&CK.** All 36 actions of the two
OpenClaw flows (18 each) use MITRE ATLAS IDs (`AML.T…`, two written as `[ATL] AML.T… <name>`).
The `ttp` fallback does not help them: after normalization (`technique_id = NULL`, original kept per
SPEC §5.4) they contribute no Enterprise technique transitions. So of the 7 "zero-edge" flows, 4 become
usable for the technique model (both Turla plans, ToolShell, Equifax), and 3 do not (OpenClaw ×2:
ATLAS-only; Example Attack Tree: unlabeled). Whether to add an ATLAS state space is a product question.

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

## P0.7 — loading

- `Equifax Breach.afb` contains a `\u0000` (NUL) inside a string; PostgreSQL `text`/`jsonb` cannot store
  it. The loader strips NULs from the document before parsing and storing; the report's `sha256` is of
  the original bytes.
- Three files carry a flow name that differs from the file name; the loader uses the in-file name
  (`flow.name`): `Equifax Breach.afb` → "Equifax Breach (with Mitigations/Detections)",
  `OpenClaw Command & Control via Prompt Injection.afb` → "... (with Mitigations/Detections)", and
  `OpenClaw.afb` → "OpenClaw Command & Control via Prompt Injection". The two OpenClaw files are the
  same scenario, one without and one with mitigations/detections: a candidate for incident dedupe
  (P0.7 review below).

### P0.7 manual dedupe review (SPEC §5.5 / TASKS P0.7)

Compared raw technique sets (Jaccard) for the groups TASKS flagged, plus one more found while reading
names. None of these flows carries actor, campaign, sector or date metadata, so the §5.5 candidate
test (same actor, 45-day window, shared victim *or* Jaccard ≥ 0.5) cannot fire on anything but
Jaccard. Decision: **all 41 flows stay separate incidents** (acceptance: 1 incident each).

| Group | Pairwise Jaccard | Verdict |
|---|---|---|
| Conti CISA Alert / Conti PWC / Conti Ransomware | 0.13, 0.08, 0.11 (2 shared techniques each) | Different reports and different technique sets; group-level TTP summaries, not one incident. Keep separate. |
| CISA AA22-138B Alt / TA1 / TA2 | Alt–TA1 **0.50** (5 shared), Alt–TA2 0.08, TA1–TA2 0.15 | The advisory describes two separate threat-actor intrusions (TA1, TA2). Keep separate. Alt–TA1 is the one borderline pair and would go to the §5.5 review queue (0.5–0.75). |
| OpenClaw / OpenClaw … Prompt Injection | **1.00** (identical 17 techniques) | Same scenario, one variant with mitigations/detections: a true duplicate. Left as two incidents for now; both are ATLAS-only so the technique model is unaffected. Merge when P2.6 dedupe exists, or sooner on request. |

Counting rule consequence: if Alt–TA1 or the OpenClaw pair were merged, transitions would be the
union per incident (§5.5), lowering the incident count by 1 each.
