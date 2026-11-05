# Search discovery and Settings

Find report URLs with Serper or Brave, review them, and fetch only what a licence-reviewed source covers. Options and API keys are set in Settings (the CLI today, the Explorer page next).

## Secrets

| Name | Used for |
|---|---|
| `SERPER_API_KEY` | `POST https://google.serper.dev/search` |
| `BRAVE_API_KEY` | `GET https://api.search.brave.com/res/v1/web/search` |

- Stored encrypted (Fernet) in `pivot.secret`. The master key is `PIVOT_SECRET_KEY`, or the file `PIVOT_SECRET_KEY_FILE` (default `DATA_DIR/pivot/secret.key`). The file is created the first time a secret is stored, mode 0600, with a `.gitignore` beside it, and is **never overwritten**. It is not in the database or a dump: back it up separately. Losing it loses only the stored secrets; they show as "unreadable" and are entered again.
- Resolution: stored value first, then the environment variable of the same name (shown as "environment", read-only). Nothing is copied from the environment into the database.
- Write-only: the API and CLI can set or delete a secret, never read it. Stored values are masked in logs and error messages; `tests/pivot/test_search.py` runs an adapter written to leak its key.

```bash
afp settings secret set SERPER_API_KEY     # prompts; or pipe the value on stdin
afp settings secret set BRAVE_API_KEY
afp settings show
```

## Options

| Key | Default | Meaning |
|---|---|---|
| `search.provider` | `off` | `off`, `serper`, `brave` or `both` |
| `search.results_per_query` | 10 | 1–20 |
| `search.freshness` | `any` | `any`, `day`, `week`, `month`, `year` |
| `search.budget.serper`, `search.budget.brave` | 100 | queries per calendar month (UTC); 0 blocks the provider |

`afp settings set KEY VALUE`, `afp settings reset KEY`. The count is kept in `pivot.search_usage` and is incremented before the request is sent, so a crash cannot under-count.

## Discovery flow

```bash
afp search run --dry-run "lazarus intrusion"   # providers, keys, budget; sends nothing
afp search run "lazarus intrusion"             # queue the results (billed by the provider)
afp search queue                               # URLs, and which source (if any) their domain maps to
afp search map thedfirreport.com "The DFIR Report"   # declare that the source's review covers this domain
afp search fetch                               # fetch queued URLs whose domain maps to an ENABLED source
afp search reject URL_OR_ID
```

A search result is a pointer, not permission. `afp search fetch` goes through `collect_source`, so the polite client's robots.txt check, rate limit and "never bypass" rules apply, and a URL on a disabled or unmapped domain stays queued. Mapping a domain does not enable its source.

## API

`/api/v1/pivot/settings` is mounted by `attack_flow_api/main.py` only when `PIVOT_DATABASE_URL` is set. Every route needs the header `X-Pivot-Admin-Token` to equal `PIVOT_ADMIN_TOKEN`; with no token configured every route returns 403 (fail closed).

| Route | |
|---|---|
| `GET /pivot/settings` | options (with description, value, default) and secret status |
| `PUT /pivot/settings/options/{key}` `{"value": …}` / `DELETE` | set / reset an option |
| `PUT /pivot/settings/secrets/{name}` `{"value": "…"}` / `DELETE` | store / remove a secret; responses carry status only |
