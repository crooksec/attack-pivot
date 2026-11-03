-- Collectors dedupe by canonical URL as well as sha256 (SPEC §6.2).
SET LOCAL search_path = pivot, public;

CREATE UNIQUE INDEX report_url_key ON report (url) WHERE url IS NOT NULL;
