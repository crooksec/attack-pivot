-- Model estimates: counts are fractional at tactic level (1/k split of multi-tactic techniques),
-- and the reproducibility hash is computed on full-precision values, so use double precision.
SET LOCAL search_path = pivot, public;

ALTER TABLE transition_estimate
    ALTER COLUMN n_ab TYPE double precision,
    ALTER COLUMN n_a TYPE double precision,
    ALTER COLUMN p_mle TYPE double precision,
    ALTER COLUMN p TYPE double precision,
    ALTER COLUMN ci_low TYPE double precision,
    ALTER COLUMN ci_high TYPE double precision;

-- SHA-256 over the run's estimates (rounded to 10 decimals); equal inputs give equal hashes.
ALTER TABLE model_run ADD COLUMN estimates_sha256 text;
