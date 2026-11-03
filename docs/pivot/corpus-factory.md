# Corpus factory: running it

The order of operations, with what each step reads and writes. Every network or LLM step is opt-in; nothing runs from `afp db init`.

```
afp sources load                       # seed registry -> pivot.source (all non-structured sources disabled)
afp sources enable NAME --reviewed-by WHO --licence TEXT   # after docs/pivot/source-review.md is filled in
afp collect [--source NAME] [--since YYYY-MM-DD] [--limit N]
afp collect --source NAME --files a.pdf b.html --tlp amber   # files you already have (ISAC: --tlp required)
afp collect --source NAME --urls urls.txt                    # an explicit URL list, still robots-checked
afp triage [--heuristics-only]         # reports -> candidate | rejected   (LLM unless --heuristics-only)
afp extract --provider P --model M     # candidates -> API jobs -> .afb -> flows/transitions (origin=llm)
afp dedupe                             # cluster flows into incidents; 0.5-0.75 pairs go to the queue
afp dedupe queue / resolve ID --merge|--distinct --by NAME
afp review sample --batch B            # 10% (cap 50) of unreviewed LLM flows, stratified by source class
afp review show FLOW / accept / correct / reject
afp review report                      # edge precision vs PRD 5.4 (>= 0.85, >= 50 flows)
afp corpus stats                       # composition and progress toward M-Proof / M-Stretch
afp triage cost                        # LLM calls and tokens logged so far
```

## Rules the code enforces
- A source runs only when `enabled`. `enable` refuses a source whose licence is empty or still says "verify".
- robots.txt is fetched once per origin: 404/410 allow; 401/403/5xx/network failure disallow. The per-host delay is the larger of the source's `rate_limit_seconds` (default 5) and `Crawl-delay`. 401/402/403/407/451 are never retried or worked around, and redirects are re-checked hop by hop.
- Report text lives only in `DATA_DIR/pivot/reports/<sha256>.txt` and is never served or exported. Dedupe is by canonical URL and sha256.
- The report's TLP is the source's `default_tlp` (ISAC imports take the TLP you pass); the flow inherits it. Public exports include `clear` only.
- Triage records its mode: `report.triage->>'mode'` is `llm`, `heuristics` (rejected before any LLM call) or `heuristics_only`.
- An extracted edge keeps its `order_basis` and `evidence_quote` (<= 200 characters). An LLM edge without a label is `inferred_llm`, which the default model run excludes.

## Prerequisites outside this repository
- `config/providers.yml` (copy `providers.yml.example`) with a provider enabled, for `afp triage`; the API running with the same file, for `afp extract` (`ATTACK_FLOW_API_URL`, default `http://localhost:8000/api/v1`).
- `docker compose -f docker-compose.api.yml up` (or any running `attack_flow_api`) for extraction.
