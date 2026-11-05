-- Settings, encrypted secrets and the search-discovery queue (docs/pivot/context/decisions.md,
-- "Search discovery and Settings"). Secret values are Fernet ciphertext; the key lives outside the database.
SET LOCAL search_path = pivot, public;

CREATE TABLE setting (
    key text PRIMARY KEY,
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE secret (
    name text PRIMARY KEY,
    ciphertext bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A domain maps to the source whose licence review covers it. Search results are fetched only through this map.
CREATE TABLE source_domain (
    domain text PRIMARY KEY CHECK (domain = lower(domain)),
    source_id uuid NOT NULL REFERENCES source (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE discovered_url (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    url text NOT NULL,
    canonical_url text NOT NULL UNIQUE,
    domain text NOT NULL,
    title text,
    snippet text,
    provider text NOT NULL CHECK (provider IN ('serper', 'brave')),
    query text NOT NULL,
    rank integer,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'fetched', 'rejected', 'failed')),
    note text,
    report_id uuid REFERENCES report (id) ON DELETE SET NULL,
    found_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz
);
CREATE INDEX discovered_url_status ON discovered_url (status, found_at DESC);
CREATE INDEX discovered_url_domain ON discovered_url (domain);

-- Queries sent per provider per calendar month (UTC), for the budget option.
CREATE TABLE search_usage (
    provider text NOT NULL CHECK (provider IN ('serper', 'brave')),
    month text NOT NULL,
    queries integer NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, month)
);
