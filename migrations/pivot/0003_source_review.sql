-- Licence/ToS review record for a source (SPEC §6.1). A source may be enabled only after review.
SET LOCAL search_path = pivot, public;

ALTER TABLE source
    ADD COLUMN reviewed_at timestamptz,
    ADD COLUMN reviewed_by text;
