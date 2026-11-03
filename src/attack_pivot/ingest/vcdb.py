"""VERIS Community Database and the CTID VERIS->ATT&CK mapping (SPEC §6.6).

VCDB is incident base rates, context and a differently-biased cross-check. This module loads
the raw records and the mapping and measures how much of VCDB can contribute ordered, mapped
transitions. It does not derive flows or transitions: see ``docs/pivot/corpus-notes.md``.
"""

import csv
import json
import logging
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

from psycopg.types.json import Jsonb

from attack_pivot.ingest.load import ensure_source, strip_nul

logger = logging.getLogger(__name__)

VCDB_URL = "https://github.com/vz-risk/VCDB.git"
MAPPING_URL = (
    "https://github.com/center-for-threat-informed-defense/attack_to_veris.git"
)
DEFAULT_MAP_VERSION = "1.3.7"
SOURCES = [
    {
        "name": "VERIS Community Database",
        "publisher": "VERIS / vz-risk",
        "source_class": "structured_dataset",
        "base_url": "https://github.com/vz-risk/VCDB",
        "collector": "github_repo",
        "default_tlp": "clear",
        "licence": "CC-BY-SA-4.0",
        "reliability": "B",
        "enabled": True,
    },
    {
        "name": "CTID VERIS-ATT&CK mapping",
        "publisher": "MITRE CTID",
        "source_class": "structured_dataset",
        "base_url": "https://github.com/center-for-threat-informed-defense/attack_to_veris",
        "collector": "github_repo",
        "default_tlp": "clear",
        "licence": "Apache-2.0",
        "reliability": "A",
        "enabled": True,
    },
]
# event_chain steps name only the VERIS action category, abbreviated.
CHAIN_CATEGORY = {
    "hak": "hacking", "mal": "malware", "soc": "social", "mis": "misuse",
    "phy": "physical", "err": "error", "env": "environmental", "unk": "unknown",
}  # fmt: skip
# Free text, not enumerations: these would swamp the path counts.
FREE_TEXT_KEYS = {"notes", "name", "cve", "amount", "other"}
AI_MARKER = re.compile(r"encoded by ai", re.I)


def _data_dir():
    return Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "repos"


def update_repos(vcdb_dir=None, mapping_dir=None):
    """
    Clone or fast-forward the two repositories: VCDB (sparse, ``data/json/validated`` only)
    and the mapping repo (shallow).

    :return: ``(vcdb_dir, mapping_dir)``
    :rtype: tuple[Path, Path]
    """
    vcdb_dir = Path(vcdb_dir) if vcdb_dir else _data_dir() / "VCDB"
    mapping_dir = Path(mapping_dir) if mapping_dir else _data_dir() / "attack_to_veris"
    if (vcdb_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(vcdb_dir), "pull", "--ff-only", "-q"], check=True
        )
    else:
        vcdb_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                VCDB_URL,
                str(vcdb_dir),
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(vcdb_dir),
                "sparse-checkout",
                "set",
                "data/json/validated",
            ],
            check=True,
        )
    if (mapping_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(mapping_dir), "pull", "--ff-only", "-q"], check=True
        )
    else:
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", MAPPING_URL, str(mapping_dir)],
            check=True,
        )
    return vcdb_dir, mapping_dir


def read_mapping(mapping_dir, veris_version=DEFAULT_MAP_VERSION):
    """
    Read the Enterprise VERIS->ATT&CK mapping CSV for a VERIS version.

    :return: ``(map_version label, rows)``; rows are ``(veris_path, technique_id, relation)``.
        Technique IDs are as declared (ATT&CK 12.1 for VERIS 1.3.7); map them to the pinned
        version with :func:`attack_pivot.normalize.attack.normalize_technique` at use time.
    :rtype: tuple[str, list[tuple]]
    """
    base = Path(mapping_dir) / "mappings" / f"veris-{veris_version}" / "input"
    try:
        config = json.loads((base / "config.json").read_text())
        path = next((base / "enterprise" / "csv").glob("*mappings-enterprise.csv"))
    except (OSError, StopIteration):
        raise RuntimeError(
            f"no VERIS {veris_version} Enterprise mapping under {mapping_dir}"
        ) from None
    label = f"veris-{config['veris_version']}/mappings-{config['mappings_version']}/attack-{config['attack_version']}"
    with path.open(encoding="utf-8-sig", newline="") as f:
        rows = [
            (
                r["VERIS PATH"].strip(),
                r["TECHNIQUE ID"].strip(),
                r["RELATIONSHIP TYPE"].strip(),
            )
            for r in csv.DictReader(f)
        ]
    return label, sorted(set(rows))


def read_records(vcdb_dir):
    """
    Yield parsed incident documents from ``data/json/validated``, each with a ``_stem`` key
    holding its file name stem (dropped again by :func:`record_row`).
    """
    for path in sorted((Path(vcdb_dir) / "data" / "json" / "validated").glob("*.json")):
        yield {**json.loads(path.read_text()), "_stem": path.stem}


def veris_paths(doc):
    """
    Every enumerated value in a record as a dotted path, e.g.
    ``action.hacking.variety.Brute force`` (the form used by the mapping's ``VERIS PATH``).
    Free-text fields (notes, names, CVEs, amounts) are skipped.

    :rtype: set[str]
    """
    found = set()

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if key not in FREE_TEXT_KEYS:
                    walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, str):
                    found.add(f"{path}.{item}")
        elif isinstance(node, str):
            found.add(f"{path}.{node}")

    for key in ("action", "attribute", "value_chain"):
        if key in doc:
            walk(doc[key], key)
    return found


def event_chain(doc):
    """The record's ordered ``plus.event_chain`` steps (possibly empty)."""
    return (doc.get("plus") or {}).get("event_chain") or []


def duplicate_ids(docs):
    """``incident_id`` values that appear in more than one file."""
    counts = Counter(doc["incident_id"] for doc in docs)
    return frozenset(i for i, n in counts.items() if n > 1)


def record_row(doc, duplicates=frozenset()):
    """
    Map a VCDB document to a ``veris_incident`` row (raw kept as ``raw``).

    The id is the record's ``incident_id``. 23 ids are shared by 67 files (44 beyond the first) holding
    different incidents; every file in such a group is keyed ``<incident_id>~<file stem>``
    instead of being collapsed into one row.

    :param frozenset duplicates: From :func:`duplicate_ids`.
    """
    stem = doc.get("_stem")
    doc = {k: v for k, v in doc.items() if k != "_stem"}
    victim = doc.get("victim") or {}
    year = ((doc.get("timeline") or {}).get("incident") or {}).get("year")
    return {
        "id": (
            f"{doc['incident_id']}~{stem}"
            if doc["incident_id"] in duplicates
            else doc["incident_id"]
        ),
        "veris_version": doc.get("schema_version"),
        "raw": strip_nul(doc),
        "year": year if isinstance(year, int) else None,
        "victim_industry": victim.get("industry"),
        "victim_size": victim.get("employee_count"),
        "actor_types": sorted((doc.get("actor") or {}).keys()),
        "has_sequence": len(event_chain(doc)) >= 2,
    }


def compute_stats(docs, mapped_paths):
    """
    Measure what VCDB can contribute (PRD R11, SPEC §6.6).

    ``has_sequence`` here means an ``event_chain`` of at least two steps, the minimum that yields
    a transition. "Fully mappable" means every step's action category has at least one
    mapped VERIS path in that record.

    :param docs: Iterable of VCDB documents.
    :param set mapped_paths: ``VERIS PATH`` values present in the mapping.
    :rtype: dict
    """
    s = Counter()
    versions, steps, pairs = Counter(), Counter(), Counter()
    seen_paths, mapped_hit, ids = Counter(), Counter(), Counter()
    for doc in docs:
        s["records"] += 1
        ids[doc.get("incident_id")] += 1
        versions[doc.get("schema_version")] += 1
        chain = event_chain(doc)
        paths = veris_paths(doc)
        mapped = paths & mapped_paths
        s["with_any_mapped_path"] += bool(mapped)
        s["with_mapped_action_path"] += any(p.startswith("action.") for p in mapped)
        for p in paths:
            seen_paths[p] += 1
            mapped_hit[p in mapped_paths] += 1
        ai = bool(
            AI_MARKER.search(
                json.dumps((doc.get("plus") or {}).get("analyst_notes", ""))
            )
        )
        s["ai_encoded"] += ai
        if chain:
            s["with_event_chain"] += 1
            steps[len(chain)] += 1
        if len(chain) >= 2:
            s["with_sequence"] += 1
            s["sequence_ai_encoded"] += ai
            cats = [CHAIN_CATEGORY.get(step.get("action")) for step in chain]
            for a, b in zip(cats, cats[1:]):
                pairs[f"{a}>{b}"] += 1
            if all(
                c and any(p.startswith(f"action.{c}.") for p in mapped) for c in cats
            ):
                s["sequence_fully_mappable"] += 1
    n, seq = s["records"] or 1, s["with_sequence"] or 1
    return {
        "records": s["records"],
        "distinct_incident_ids": len(ids),
        "duplicate_incident_id_files": s["records"] - len(ids),
        "veris_versions": dict(versions.most_common()),
        "with_event_chain": s["with_event_chain"],
        "with_event_chain_pct": round(100 * s["with_event_chain"] / n, 1),
        "with_sequence": s["with_sequence"],
        "with_sequence_pct": round(100 * s["with_sequence"] / n, 1),
        "chain_length_histogram": dict(sorted(steps.items())),
        "top_category_pairs": dict(pairs.most_common(8)),
        "records_with_any_mapped_path_pct": round(
            100 * s["with_any_mapped_path"] / n, 1
        ),
        "records_with_mapped_action_path_pct": round(
            100 * s["with_mapped_action_path"] / n, 1
        ),
        "distinct_veris_paths_in_vcdb": len(seen_paths),
        "distinct_paths_mapped_pct": round(
            100
            * sum(1 for p in seen_paths if p in mapped_paths)
            / max(1, len(seen_paths)),
            1,
        ),
        "path_occurrences_mapped_pct": round(
            100 * mapped_hit[True] / max(1, mapped_hit[True] + mapped_hit[False]), 1
        ),
        "sequence_fully_mappable": s["sequence_fully_mappable"],
        "sequence_fully_mappable_pct_of_sequence": round(
            100 * s["sequence_fully_mappable"] / seq, 1
        ),
        "sequence_fully_mappable_pct_of_records": round(
            100 * s["sequence_fully_mappable"] / n, 1
        ),
        "ai_encoded": s["ai_encoded"],
        "sequence_ai_encoded": s["sequence_ai_encoded"],
    }


def load(conn, docs, map_label, mapping_rows, duplicates=frozenset()):
    """
    Upsert VCDB records and the mapping (replacing that ``map_version`` wholesale). Records that
    are no longer in the data and have no derived flow are removed.

    :return: ``{"veris_incidents": n, "mapping_rows": n}``
    :rtype: dict
    """
    for source in SOURCES:
        ensure_source(conn, source)
    n = 0
    sql = (
        "INSERT INTO pivot.veris_incident (id, veris_version, raw, year, victim_industry, victim_size, "
        "actor_types, has_sequence, imported_at) VALUES (%(id)s, %(veris_version)s, %(raw)s, %(year)s, "
        "%(victim_industry)s, %(victim_size)s, %(actor_types)s, %(has_sequence)s, now()) "
        "ON CONFLICT (id) DO UPDATE SET veris_version = EXCLUDED.veris_version, raw = EXCLUDED.raw, "
        "year = EXCLUDED.year, victim_industry = EXCLUDED.victim_industry, victim_size = EXCLUDED.victim_size, "
        "actor_types = EXCLUDED.actor_types, has_sequence = EXCLUDED.has_sequence, imported_at = now()"
    )
    with conn.cursor() as cur:
        batch = []
        for doc in docs:
            row = record_row(doc, duplicates)
            batch.append({**row, "raw": Jsonb(row["raw"])})
            if len(batch) == 500:
                cur.executemany(sql, batch)
                n += len(batch)
                batch = []
        if batch:
            cur.executemany(sql, batch)
            n += len(batch)
        cur.execute(
            "DELETE FROM pivot.veris_incident WHERE imported_at < now() AND flow_id IS NULL"
        )
        cur.execute(
            "DELETE FROM pivot.veris_attack_map WHERE map_version = %s", (map_label,)
        )
        cur.executemany(
            "INSERT INTO pivot.veris_attack_map (veris_path, technique_id, map_version, relation) "
            "VALUES (%s, %s, %s, %s)",
            [(path, tid, map_label, rel) for path, tid, rel in mapping_rows],
        )
    conn.commit()
    return {"veris_incidents": n, "mapping_rows": len(mapping_rows)}
