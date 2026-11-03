-- P2: triage record on the report, and a cost log for every LLM call the corpus factory makes
-- (SPEC §6.3 triage, §6.4 "cost logging").
SET LOCAL search_path = pivot, public;

ALTER TABLE report ADD COLUMN triage jsonb;   -- heuristics, LLM answer, decision mode

CREATE TABLE llm_call (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose text NOT NULL CHECK (purpose IN ('triage', 'extract')),
    report_id uuid REFERENCES report (id) ON DELETE SET NULL,
    provider text,
    model text,
    input_tokens integer,
    output_tokens integer,
    latency_ms integer,
    job_id text,
    ok boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX llm_call_purpose ON llm_call (purpose, created_at);
