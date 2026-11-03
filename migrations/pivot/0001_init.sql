-- ATT&CK-pivot relational schema (SPEC §4). Source of truth; the AGE graph is derived.
-- WARNING: the AGE graph is named 'pivot' and AGE keeps graph tables in a Postgres schema of
-- the same name, i.e. this schema. NEVER call ag_catalog.drop_graph('pivot', true): the CASCADE
-- drops every table below. Rebuild the graph by deleting its vertices/edges instead.

CREATE SCHEMA IF NOT EXISTS pivot;
SET LOCAL search_path = pivot, public;

-- ---------------------------------------------------------------- provenance
CREATE TABLE source (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    publisher text,
    source_class text NOT NULL CHECK (source_class IN (
        'government', 'vendor', 'isac', 'independent', 'emulation', 'academic',
        'community', 'structured_dataset', 'detection_repo', 'other')),
    base_url text,
    collector text,
    collector_config jsonb,
    default_tlp text NOT NULL DEFAULT 'clear'
        CHECK (default_tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red')),
    licence text,
    reliability char(1) CHECK (reliability IN ('A', 'B', 'C', 'D', 'E', 'F')),
    notes text,
    enabled boolean NOT NULL DEFAULT false,  -- SPEC §6.1: sources stay disabled until licence-reviewed
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE report (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id uuid REFERENCES source (id),
    url text,
    title text,
    published_at date,
    retrieved_at timestamptz,
    sha256 text UNIQUE,
    tlp text CHECK (tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red')),
    credibility smallint CHECK (credibility BETWEEN 1 AND 6),
    text_path text,                -- local file, never exported
    api_input_source_id text,      -- FK-by-value to attack_flow_api input_sources
    triage_status text CHECK (triage_status IN ('new', 'candidate', 'rejected', 'extracted', 'failed')),
    triage_reason text,
    technique_mentions int,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE incident (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    label text,
    first_seen date,
    last_seen date,
    cluster_method text,
    cluster_confidence real,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE report_incident (
    report_id uuid NOT NULL REFERENCES report (id) ON DELETE CASCADE,
    incident_id uuid NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    link_confidence real,
    method text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, incident_id)
);

-- ------------------------------------------------------ flows and observations
CREATE TABLE flow (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id uuid REFERENCES report (id),
    incident_id uuid REFERENCES incident (id),
    name text,
    origin text NOT NULL CHECK (origin IN ('upstream_corpus', 'manual', 'llm', 'stix_import')),
    llm_provider text,
    llm_model text,
    api_job_id text,
    attack_version text,
    afb jsonb,
    stix jsonb,
    review_status text NOT NULL DEFAULT 'unreviewed'
        CHECK (review_status IN ('unreviewed', 'accepted', 'corrected', 'rejected')),
    reviewer text,
    reviewed_at timestamptz,
    tlp text CHECK (tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE action_obs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id uuid NOT NULL REFERENCES flow (id) ON DELETE CASCADE,
    node_ref text NOT NULL,        -- afb instance id / STIX id
    technique_id text,             -- normalized; NULL if unlabeled or unmappable
    technique_id_original text,    -- as extracted
    tactic_id text,
    name text,
    confidence smallint,
    execution_start timestamptz,
    execution_end timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (flow_id, node_ref)
);

CREATE TABLE transition_obs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id uuid NOT NULL REFERENCES flow (id) ON DELETE CASCADE,
    incident_id uuid REFERENCES incident (id),
    src_action uuid NOT NULL REFERENCES action_obs (id) ON DELETE CASCADE,
    dst_action uuid NOT NULL REFERENCES action_obs (id) ON DELETE CASCADE,
    src_technique text,            -- normalized
    dst_technique text,
    order_basis text NOT NULL CHECK (order_basis IN (
        'explicit', 'timestamp', 'inferred_narrative', 'mapped_sequence', 'inferred_llm', 'unordered')),
    fidelity text NOT NULL DEFAULT 'technique' CHECK (fidelity IN ('technique', 'mapped_coarse')),
    via text NOT NULL DEFAULT 'direct'
        CHECK (via IN ('direct', 'and', 'or', 'condition_true', 'condition_false')),
    delta_seconds bigint,
    evidence_quote text CHECK (evidence_quote IS NULL OR char_length(evidence_quote) <= 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------- context (stored now, modelled in v2)
CREATE TABLE actor (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_group_id text UNIQUE,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE actor_alias (
    actor_id uuid NOT NULL REFERENCES actor (id) ON DELETE CASCADE,
    alias text NOT NULL,
    source text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (actor_id, alias)
);

CREATE TABLE flow_actor (
    flow_id uuid NOT NULL REFERENCES flow (id) ON DELETE CASCADE,
    actor_id uuid NOT NULL REFERENCES actor (id),
    attribution_confidence real,
    basis text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (flow_id, actor_id)
);

CREATE TABLE flow_context (
    flow_id uuid PRIMARY KEY REFERENCES flow (id) ON DELETE CASCADE,
    sectors text[],
    platforms text[],
    regions text[],
    victim_org_size text,
    initial_access_vector text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------ ATT&CK reference (versioned)
CREATE TABLE attack_version (
    version text PRIMARY KEY,
    released date,
    stix_url text,
    synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE technique (
    attack_id text NOT NULL,
    version text NOT NULL REFERENCES attack_version (version),
    name text NOT NULL,
    parent_id text,
    tactic_ids text[],
    platforms text[],
    revoked boolean NOT NULL DEFAULT false,
    deprecated boolean NOT NULL DEFAULT false,
    stix_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (attack_id, version)
);

CREATE TABLE technique_replacement (   -- revoked-by
    from_id text NOT NULL,
    to_id text NOT NULL,
    version text NOT NULL REFERENCES attack_version (version),
    relation text NOT NULL DEFAULT 'revoked-by',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (from_id, to_id, version, relation)
);

CREATE TABLE tactic (
    attack_id text NOT NULL,
    version text NOT NULL REFERENCES attack_version (version),
    name text NOT NULL,
    shortname text,
    ord smallint,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (attack_id, version)
);

-- ------------------------------------------------------------------------ model
CREATE TABLE model_run (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    label text,
    attack_version text,
    params jsonb,
    corpus_filter jsonb,
    corpus_stats jsonb,
    eval jsonb,
    is_active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX model_run_one_active ON model_run (is_active) WHERE is_active;

CREATE TABLE transition_estimate (
    run_id uuid NOT NULL REFERENCES model_run (id) ON DELETE CASCADE,
    level text NOT NULL CHECK (level IN ('subtechnique', 'technique', 'tactic')),
    src text NOT NULL,
    dst text NOT NULL,
    n_ab int NOT NULL,
    n_a int NOT NULL,
    p_mle real,
    p real NOT NULL,
    ci_low real NOT NULL,
    ci_high real NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, level, src, dst)
);

-- ------------------------------------------------------- detection analytics (CAR)
CREATE TABLE analytic (
    id text PRIMARY KEY,           -- e.g. CAR-2020-09-001
    repo text NOT NULL DEFAULT 'car',
    title text,
    information_domain text,
    platforms text[],
    data_model_refs text[],
    url text,
    raw jsonb,
    synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE analytic_technique (
    analytic_id text NOT NULL REFERENCES analytic (id) ON DELETE CASCADE,
    technique_id text NOT NULL,
    tactic_id text,
    coverage text,                 -- as declared by CAR (Low/Moderate/High) if present
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (analytic_id, technique_id)
);

-- --------------------------------------------------------------------- VERIS / VCDB
CREATE TABLE veris_incident (
    id text PRIMARY KEY,           -- VCDB incident_id
    veris_version text,
    raw jsonb,
    year smallint,
    victim_industry text,
    victim_size text,
    actor_types text[],
    has_sequence boolean NOT NULL DEFAULT false,
    flow_id uuid REFERENCES flow (id),
    imported_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE veris_attack_map (    -- from center-for-threat-informed-defense/attack_to_veris
    veris_path text NOT NULL,
    technique_id text NOT NULL,
    map_version text NOT NULL,
    relation text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (veris_path, technique_id, map_version)
);

-- ---------------------------------------------------------------------- coverage
CREATE TABLE coverage_layer (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    navigator jsonb,
    attack_version text,
    imported_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE coverage_item (
    layer_id uuid NOT NULL REFERENCES coverage_layer (id) ON DELETE CASCADE,
    technique_id text NOT NULL,
    score real,
    covered boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (layer_id, technique_id)
);

-- ---------------------------------------------------------------------- indexes
CREATE INDEX transition_obs_techniques ON transition_obs (src_technique, dst_technique);
CREATE INDEX transition_obs_incident ON transition_obs (incident_id);
CREATE INDEX transition_obs_flow ON transition_obs (flow_id);
CREATE INDEX transition_estimate_run_level_src ON transition_estimate (run_id, level, src);
CREATE INDEX flow_incident ON flow (incident_id);
CREATE INDEX flow_report ON flow (report_id);
CREATE INDEX action_obs_flow ON action_obs (flow_id);
CREATE INDEX action_obs_technique ON action_obs (technique_id);
CREATE INDEX report_source ON report (source_id);
CREATE INDEX analytic_technique_technique ON analytic_technique (technique_id);
-- report(sha256) is already indexed by its UNIQUE constraint.
