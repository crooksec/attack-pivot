# Running the corpus factory on local models

The app's provider layer (`config/providers.yml`, LiteLLM) already accepts any OpenAI-compatible server through `provider_type: openai_compatible`, so triage (`afp triage`) and extraction (`afp extract`, through the API job pipeline) can run on models on this Mac with no hosted key. Nothing in the pivot code is specific to a vendor.

## Rules for this machine

- **The GPU is shared.** Another project uses the local models. Do not send a request to a local server (not even a probe) until its owner says it is free. Everything below marked **needs a model** waits for that.
- Everything marked **no model** (`--dry-run`, config checks, tests, ingest of local files) can run any time.
- Run one request at a time (`--concurrency 1`). A local server queues requests anyway, and parallel jobs only raise the chance of a timeout.

## Config (no model)

`config/providers.yml` is gitignored. Add a provider that points at the local server's OpenAI-compatible base URL. The URL and model id are the server's, not this repo's: take them from the server's own start-up line or its model list.

```yaml
providers:
  - provider_id: local
    provider_type: openai_compatible
    enabled: true
    base_url: http://127.0.0.1:PORT/v1   # the server that is serving the model
    api_key_env: LOCAL_LLM_API_KEY       # any non-empty value if the server ignores keys
    default_model: MODEL_ID              # exactly what the server expects
    allowed_models:
      - MODEL_ID
```

Models on disk (LM Studio folder) that are candidates: Qwen3.8-27B (MLX, 8-bit) and Qwen3.6-35B-A3B (MLX, 4-bit). Which one is loaded, and under what id, is decided when the server is started.

Known unknowns until a request is made:
1. The adapter asks for `response_format: {"type": "json_object"}`. A server that rejects that field will fail every call; one that ignores it is fine, because replies are parsed tolerantly.
2. Some models write reasoning first (`<think>…</think>`). `llm.parse_json_object` strips those blocks, but the reasoning counts against the token limit.
3. The API's job audit does not record tokens, so extraction rows in `pivot.llm_call` have no token counts.

## Limits for slow models

| Setting | Default | Local-model advice |
|---|---|---|
| `PIVOT_LLM_TIMEOUT` (triage call, seconds) | 60 | 300–600 |
| `PIVOT_LLM_MAX_OUTPUT_TOKENS` (triage answer) | 400 | 1500–2000 if the model reasons first |
| `afp extract --timeout` (one job, seconds) | 900 | raise for long reports |
| `afp extract --concurrency` | 4 | 1 |

## Before spending model time (no model)

```bash
afp triage --dry-run          # reports, heuristic rejects, LLM calls, ~input tokens
afp extract --dry-run         # candidate reports and characters
afp corpus stats
```

`--dry-run` builds no client and contacts nothing. Use it to size a run, then pick `--limit`.

## Order of work once the model is free (needs a model)

1. Start the API with the local provider enabled; confirm the provider list shows `local`.
2. Triage a handful: `afp triage --limit 5`. Read the `reason` strings in `report.triage` and `afp triage cost`.
3. Extract two or three: `afp extract --limit 3 --concurrency 1`; open the `.afb` files in the Builder and read the `x_order_basis` / `x_evidence_quote` values on the lines.
4. Only then scale, in batches, and run `afp review sample` on each batch.

Local models are not a different bar: the review sample (PRD §5.4, ≥ 85% direction and `order_basis` correct) applies to every `origin=llm` flow, whichever model wrote it, and `llm_call` records the provider and model so results can be split by model.

## Inputs

No network collection is needed. `afp collect --source NAME --files report1.pdf report2.html` imports reports a person saved (the source must be enabled; ISAC sources also need `--tlp`). Reports are stored locally by hash and never served.
