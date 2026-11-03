-- Incident dedupe review queue (SPEC §5.5): pairs scored 0.5-0.75, plus reviewer "not the same" decisions.
SET LOCAL search_path = pivot, public;

CREATE TABLE dedupe_candidate (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_a uuid NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    incident_b uuid NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    score real NOT NULL,
    signals jsonb NOT NULL,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'distinct')),
    decided_by text,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (incident_a < incident_b),
    UNIQUE (incident_a, incident_b)
);
CREATE INDEX dedupe_candidate_open ON dedupe_candidate (status, score DESC);
