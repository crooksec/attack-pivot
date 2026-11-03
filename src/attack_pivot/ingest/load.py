"""Load parsed flows into the pivot tables (SPEC §4, §5)."""

import hashlib
import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

from psycopg.types.json import Jsonb

from attack_pivot.ingest.afb import parse_afb
from attack_pivot.ingest.stix import parse_stix
from attack_pivot.normalize import actors as actor_names
from attack_pivot.normalize import attack

logger = logging.getLogger(__name__)

UPSTREAM_SOURCE = {
    "name": "Attack Flow upstream corpus",
    "publisher": "MITRE CTID",
    "source_class": "independent",
    "base_url": "https://github.com/center-for-threat-informed-defense/attack-flow/tree/main/corpus",
    "collector": "manual",
    "default_tlp": "clear",
    "licence": "Apache-2.0",
    "reliability": "A",
    "enabled": True,
}
EMULATION_SOURCE = {
    "name": "CTID Adversary Emulation Library",
    "publisher": "MITRE CTID",
    "source_class": "emulation",
    "base_url": "https://github.com/center-for-threat-informed-defense/adversary_emulation_library",
    "collector": "github_repo",
    "default_tlp": "clear",
    "licence": "Apache-2.0",
    "reliability": "A",
    "enabled": True,
}
MANUAL_SOURCE = {
    "name": "Manual import",
    "publisher": None,
    "source_class": "other",
    "base_url": None,
    "collector": "manual",
    "default_tlp": "amber",
    "licence": None,
    "reliability": "F",
    "enabled": True,
}
UPSTREAM_URL = "https://github.com/center-for-threat-informed-defense/attack-flow/blob/main/corpus/{name}"

# Upstream corpus flows that are CTID emulation plans: ordered, but a separate source class (R1).
EMULATION_FLOWS = {"Turla - Carbon Emulation Plan", "Turla - Snake Emulation Plan"}

# Flows whose edges are known not to be temporal order (checked during P0.5).
UNORDERED_FLOWS = {"Example Attack Tree"}


def ensure_source(conn, fields):
    """Insert a source by name if it is missing; return its id."""
    row = conn.execute(
        "SELECT id FROM pivot.source WHERE name = %s", (fields["name"],)
    ).fetchone()
    if row:
        return row["id"]
    cols = ", ".join(fields)
    marks = ", ".join(f"%({k})s" for k in fields)
    return conn.execute(
        f"INSERT INTO pivot.source ({cols}) VALUES ({marks}) RETURNING id", fields
    ).fetchone()["id"]


def latest_attack_version(conn):
    """The most recently released ATT&CK version in the database, or ``None``."""
    rows = conn.execute("SELECT version, released FROM pivot.attack_version").fetchall()

    def key(row):
        numbers = tuple(int(x) if x.isdigit() else 0 for x in row["version"].split("."))
        return (row["released"] is not None, row["released"], numbers)

    return max(rows, key=key)["version"] if rows else None


def strip_nul(value):
    """Remove NUL characters, which PostgreSQL ``text``/``jsonb`` cannot hold, from a JSON tree."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    return value


def _seconds(start, end):
    try:
        return int(
            (
                datetime.fromisoformat(end) - datetime.fromisoformat(start)
            ).total_seconds()
        )
    except (TypeError, ValueError):
        return None


def _date(text):
    """
    Calendar date of an ISO timestamp, or ``None``. Timestamps in or before 1970 are relative
    "day zero" placeholders (e.g. DFIR - BumbleBee Round 2 uses 1970-01-01T12:05), not dates.
    """
    if not text or int(text[:4]) <= 1970:
        return None
    return text[:10]


def ingest_flow(
    conn, parsed, raw, kind, *, path_name, sha256, version, index, source_id, tlp
):
    """
    Write one parsed flow: report, incident, flow, actions, transitions, actors, context.

    :param ParsedFlow parsed:
    :param dict raw: The source document, stored in ``flow.afb`` or ``flow.stix``.
    :param str kind: ``"afb"`` or ``"stix"``.
    :return: Summary counts for this flow.
    :rtype: dict
    """
    upstream = kind == "afb"
    origin = "upstream_corpus" if upstream else "stix_import"
    report_id = conn.execute(
        "INSERT INTO pivot.report (source_id, url, title, retrieved_at, sha256, tlp, "
        "triage_status) VALUES (%s, %s, %s, now(), %s, %s, 'extracted') RETURNING id",
        (
            source_id,
            UPSTREAM_URL.format(name=path_name) if upstream else None,
            parsed.name,
            sha256,
            tlp,
        ),
    ).fetchone()["id"]

    times = [
        t for a in parsed.actions for t in (a.execution_start, a.execution_end) if t
    ]
    real = [t for t in times if _date(t)]
    incident_id = conn.execute(
        "INSERT INTO pivot.incident (label, first_seen, last_seen, cluster_method, "
        "cluster_confidence) VALUES (%s, %s, %s, 'singleton', 1.0) RETURNING id",
        (parsed.name, _date(min(real, default=None)), _date(max(real, default=None))),
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO pivot.report_incident (report_id, incident_id, link_confidence, method) "
        "VALUES (%s, %s, 1.0, 'singleton')",
        (report_id, incident_id),
    )
    flow_id = conn.execute(
        "INSERT INTO pivot.flow (report_id, incident_id, name, origin, attack_version, afb, stix, "
        "review_status, tlp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (
            report_id,
            incident_id,
            parsed.name,
            origin,
            version,
            Jsonb(raw) if upstream else None,
            None if upstream else Jsonb(raw),
            "accepted" if upstream else "unreviewed",
            tlp,
        ),
    ).fetchone()["id"]

    counts = Counter()
    action_ids, techniques = {}, {}
    for a in parsed.actions:
        normalized = None
        if a.technique_id:
            normalized, _ = attack.normalize_technique(a.technique_id, index)
            counts["labeled"] += 1
            if normalized is None:
                counts["unmappable"] += 1
            elif normalized != a.technique_id:
                counts["renamed"] += 1
        action_ids[a.node_ref] = conn.execute(
            "INSERT INTO pivot.action_obs (flow_id, node_ref, technique_id, technique_id_original, "
            "tactic_id, name, confidence, execution_start, execution_end) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                flow_id,
                a.node_ref,
                normalized,
                a.technique_id,
                a.tactic_id,
                a.name,
                a.confidence,
                a.execution_start,
                a.execution_end,
            ),
        ).fetchone()["id"]
        techniques[a.node_ref] = normalized
    counts["actions"] = len(parsed.actions)

    order_basis = "unordered" if parsed.name in UNORDERED_FLOWS else "explicit"
    by_ref = {a.node_ref: a for a in parsed.actions}
    for e in parsed.edges:
        conn.execute(
            "INSERT INTO pivot.transition_obs (flow_id, incident_id, src_action, dst_action, "
            "src_technique, dst_technique, order_basis, via, delta_seconds) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                flow_id,
                incident_id,
                action_ids[e.src],
                action_ids[e.dst],
                techniques[e.src],
                techniques[e.dst],
                order_basis,
                e.via,
                _seconds(by_ref[e.src].execution_start, by_ref[e.dst].execution_end),
            ),
        )
    counts["transitions"] = len(parsed.edges)

    aliases = actor_names.load_aliases(conn)
    for actor in parsed.actors:
        actor_id, basis, confidence = actor_names.match_actor(actor["name"], aliases)
        if actor_id is None:
            actor_id = conn.execute(
                "INSERT INTO pivot.actor (name) VALUES (%s) RETURNING id",
                (actor["name"],),
            ).fetchone()["id"]
            conn.execute(
                "INSERT INTO pivot.actor_alias (actor_id, alias, source) VALUES (%s, %s, 'flow')",
                (actor_id, actor["name"]),
            )
        conn.execute(
            "INSERT INTO pivot.flow_actor (flow_id, actor_id, attribution_confidence, basis) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (flow_id, actor_id, confidence, basis),
        )
        counts["actors"] += 1
    if parsed.sectors or parsed.regions:
        conn.execute(
            "INSERT INTO pivot.flow_context (flow_id, sectors, regions) VALUES (%s, %s, %s)",
            (flow_id, parsed.sectors, parsed.regions),
        )
    return counts


def ingest_paths(conn, paths, *, version=None, tlp=None):
    """
    Ingest ``.afb`` and STIX ``.json`` files, one transaction per file, skipping known SHA-256s.

    ``.afb`` files are the upstream corpus (TLP:CLEAR, accepted). Anything else is a manual
    STIX import: TLP defaults to ``amber`` (fail closed) unless ``tlp`` is given.

    :param list[Path] paths:
    :param str version: ATT&CK version to normalize to; defaults to the latest synced.
    :return: ``(ingested, skipped, counts)``
    :rtype: tuple
    """
    version = version or latest_attack_version(conn)
    if not version:
        raise RuntimeError(
            "no ATT&CK version in the database; run `afp attack sync` first"
        )
    index = attack.load_index(conn, version)
    if not index.valid:
        raise RuntimeError(f"ATT&CK {version} has no techniques; run `afp attack sync`")
    upstream_source = ensure_source(conn, UPSTREAM_SOURCE)
    manual_source = ensure_source(conn, MANUAL_SOURCE)
    emulation_source = ensure_source(conn, EMULATION_SOURCE)
    conn.commit()

    ingested, skipped, total = [], [], Counter()
    for path in map(Path, paths):
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        if conn.execute(
            "SELECT 1 FROM pivot.report WHERE sha256 = %s", (sha256,)
        ).fetchone():
            skipped.append(path.name)
            continue
        raw = strip_nul(json.loads(data))
        if path.suffix == ".afb":
            parsed, kind, source_id, flow_tlp = (
                parse_afb(raw, name=path.stem),
                "afb",
                upstream_source,
                "clear",
            )
            if parsed.name in EMULATION_FLOWS:
                source_id = emulation_source
        else:
            parsed, kind, source_id, flow_tlp = (
                parse_stix(raw, name=path.stem),
                "stix",
                manual_source,
                tlp or "amber",
            )
        try:
            counts = ingest_flow(
                conn, parsed, raw, kind, path_name=path.name, sha256=sha256, version=version,
                index=index, source_id=source_id, tlp=flow_tlp,
            )  # fmt: skip
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        ingested.append(path.name)
        total.update(counts)
    return ingested, skipped, total
