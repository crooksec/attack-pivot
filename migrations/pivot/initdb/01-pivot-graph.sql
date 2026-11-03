-- Runs once on first container start (docker-entrypoint-initdb.d), after the
-- image's own 00-create-extension-age.sql. Idempotent so it can be re-run by hand.
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'pivot_graph') THEN
        PERFORM ag_catalog.create_graph('pivot_graph');
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS pivot;
