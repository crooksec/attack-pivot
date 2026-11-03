-- Review queue (SPEC §6.5): sampled batches, and a log of every reviewer verdict on an edge, from
-- which the edge-direction / order_basis precision of PRD §5.4 is computed.
SET LOCAL search_path = pivot, public;

ALTER TABLE flow ADD COLUMN review_batch text;
CREATE INDEX flow_review_batch ON flow (review_batch) WHERE review_batch IS NOT NULL;

CREATE TABLE review_edge (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id uuid NOT NULL REFERENCES flow (id) ON DELETE CASCADE,
    verdict text NOT NULL CHECK (verdict IN (
        'correct', 'flipped', 'basis_changed', 'flipped_and_basis_changed', 'spurious', 'missed')),
    original jsonb,                -- src/dst technique and order_basis as extracted
    reviewer text NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX review_edge_flow ON review_edge (flow_id);
