"""Source registry: load ``sources.seed.yaml`` and manage the reviewed/enabled state (SPEC §6.1)."""

import logging
from pathlib import Path

import yaml
from psycopg.types.json import Jsonb

logger = logging.getLogger(__name__)

SOURCE_CLASSES = {
    "government", "vendor", "isac", "independent", "emulation", "academic", "community",
    "structured_dataset", "detection_repo", "other",
}  # fmt: skip
COLLECTORS = {"rss", "sitemap", "github_repo", "api", "manual"}
TLPS = {"clear", "green", "amber", "amber+strict", "red"}
RELIABILITY = set("ABCDEF")
DEFAULT_RATE_LIMIT_SECONDS = 5

# Columns the YAML owns. ``enabled`` and the review record belong to the database after the first
# load, so reloading the seed can never silently re-enable or disable a source.
SEED_COLUMNS = (
    "publisher", "source_class", "base_url", "collector", "collector_config", "default_tlp",
    "licence", "reliability", "notes",
)  # fmt: skip
SEED_REVIEWER = "seed"


def read_seed(path):
    """
    Parse and validate a registry seed file.

    :param Path path:
    :return: One dict per source with the file ``defaults`` applied.
    :rtype: list[dict]
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults") or {}
    rows, seen = [], set()
    for entry in data.get("sources") or []:
        merged = {**defaults, **entry}
        name = merged.get("name")
        if not name:
            raise RuntimeError(f"source without a name: {entry!r}")
        if name in seen:
            raise RuntimeError(f"duplicate source name {name!r}")
        seen.add(name)
        problems = []
        if merged.get("source_class") not in SOURCE_CLASSES:
            problems.append(f"source_class {merged.get('source_class')!r}")
        if merged.get("collector") not in COLLECTORS:
            problems.append(f"collector {merged.get('collector')!r}")
        if merged.get("default_tlp") not in TLPS:
            problems.append(f"default_tlp {merged.get('default_tlp')!r}")
        if merged.get("reliability") and merged["reliability"] not in RELIABILITY:
            problems.append(f"reliability {merged.get('reliability')!r}")
        if problems:
            raise RuntimeError(f"source {name!r}: invalid " + ", ".join(problems))
        config = dict(merged.get("collector_config") or {})
        config.setdefault(
            "rate_limit_seconds",
            merged.get("rate_limit_seconds", DEFAULT_RATE_LIMIT_SECONDS),
        )
        rows.append(
            {
                "name": name,
                **{c: merged.get(c) for c in SEED_COLUMNS if c != "collector_config"},
                "collector_config": config,
                "enabled": bool(merged.get("enabled", False)),
            }
        )
    return rows


def load(conn, rows):
    """
    Upsert sources by name. New sources take ``enabled`` from the seed (and are stamped as
    reviewed by ``seed`` when enabled); existing sources keep their ``enabled`` and review record.

    :return: ``{"inserted": n, "updated": n, "not_in_seed": [names]}``
    :rtype: dict
    """
    inserted = updated = 0
    for row in rows:
        values = {**row, "collector_config": Jsonb(row["collector_config"])}
        existing = conn.execute(
            "SELECT id FROM pivot.source WHERE name = %s", (row["name"],)
        ).fetchone()
        if existing:
            sets = ", ".join(f"{c} = %({c})s" for c in SEED_COLUMNS)
            conn.execute(
                f"UPDATE pivot.source SET {sets} WHERE name = %(name)s", values
            )
            updated += 1
        else:
            cols = ("name", *SEED_COLUMNS, "enabled")
            conn.execute(
                f"INSERT INTO pivot.source ({', '.join(cols)}, reviewed_at, reviewed_by) "
                f"VALUES ({', '.join(f'%({c})s' for c in cols)}, "
                "CASE WHEN %(enabled)s THEN now() END, "
                "CASE WHEN %(enabled)s THEN %(reviewer)s END)",
                {**values, "reviewer": SEED_REVIEWER},
            )
            inserted += 1
    names = [r["name"] for r in rows]
    extra = [
        r["name"]
        for r in conn.execute(
            "SELECT name FROM pivot.source WHERE NOT (name = ANY(%s)) ORDER BY name",
            (names,),
        )
    ]
    conn.commit()
    return {"inserted": inserted, "updated": updated, "not_in_seed": extra}


def list_sources(conn, enabled=None):
    where, params = (
        ("WHERE enabled = %s", (enabled,)) if enabled is not None else ("", ())
    )
    return conn.execute(
        "SELECT name, source_class, collector, default_tlp, reliability, licence, enabled, "
        f"reviewed_at, reviewed_by FROM pivot.source {where} ORDER BY source_class, name",
        params,
    ).fetchall()


def unreviewed_licence(licence):
    """True when a licence string is empty or still marked for verification."""
    return not licence or "verify" in licence.lower()


def enable(conn, name, reviewed_by, licence=None):
    """
    Mark a source reviewed and enabled. Fails closed: refuses a source whose licence is empty or
    still reads "verify", unless the reviewer supplies the verified ``licence``.
    """
    row = conn.execute(
        "SELECT licence, collector FROM pivot.source WHERE name = %s", (name,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"no source named {name!r}")
    licence = licence or row["licence"]
    if unreviewed_licence(licence):
        raise RuntimeError(
            f"{name!r}: licence is {licence!r}; record the verified licence with --licence"
        )
    if not reviewed_by:
        raise RuntimeError("--reviewed-by is required")
    conn.execute(
        "UPDATE pivot.source SET enabled = true, licence = %s, reviewed_at = now(), "
        "reviewed_by = %s WHERE name = %s",
        (licence, reviewed_by, name),
    )
    conn.commit()


def disable(conn, name):
    cur = conn.execute(
        "UPDATE pivot.source SET enabled = false WHERE name = %s", (name,)
    )
    if cur.rowcount == 0:
        raise RuntimeError(f"no source named {name!r}")
    conn.commit()
