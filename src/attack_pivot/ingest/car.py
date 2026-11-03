"""MITRE CAR detection analytics (SPEC §6.6).

CAR is the detection side of the graph, not transition data: it fills ``analytic`` and
``analytic_technique`` and yields the "CAR baseline" coverage layer.
"""

import json
import logging
import os
import subprocess
from pathlib import Path

import yaml
from psycopg.types.json import Jsonb

from attack_pivot.ingest.load import ensure_source
from attack_pivot.normalize import attack

logger = logging.getLogger(__name__)

REPO_URL = "https://github.com/mitre-attack/car.git"
ANALYTIC_URL = "https://car.mitre.org/analytics/{id}/"
LAYER_NAME = "CAR baseline"
SOURCE = {
    "name": "MITRE CAR",
    "publisher": "MITRE",
    "source_class": "detection_repo",
    "base_url": "https://github.com/mitre-attack/car",
    "collector": "github_repo",
    "default_tlp": "clear",
    "licence": "Apache-2.0",
    "reliability": "A",
    "enabled": True,
}
# CAR declares Low / Moderate / High; a few analytics say "Medium". Kept as declared; this
# ranking only picks the strongest when one technique is listed twice for the same analytic.
COVERAGE_RANK = {"low": 1, "moderate": 2, "medium": 2, "high": 3}


def repo_dir():
    """Default checkout location: ``DATA_DIR``/pivot/repos/car."""
    return Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "repos" / "car"


def update_repo(directory=None):
    """
    Clone the CAR repo (shallow) or fast-forward an existing checkout.

    :return: The checkout path.
    :rtype: Path
    """
    directory = Path(directory) if directory else repo_dir()
    if (directory / ".git").exists():
        subprocess.run(
            ["git", "-C", str(directory), "pull", "--ff-only", "-q"], check=True
        )
    else:
        directory.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", "-q", REPO_URL, str(directory)], check=True
        )
    return directory


def parse_analytic(doc):
    """
    Turn one CAR analytic document into ``(analytic row, technique rows)``.

    Like CAR's own Navigator generator, both a coverage entry's ``technique`` and each of its
    ``subtechniques`` count as covered. ``tactic_id`` is kept only when the entry names exactly one
    tactic (the full document is in ``raw``).

    :param dict doc: Parsed YAML.
    :rtype: tuple[dict, list[dict]]
    """
    analytic = {
        "id": doc["id"],
        "title": doc.get("title"),
        "information_domain": doc.get("information_domain"),
        "platforms": list(doc.get("platforms") or []),
        "data_model_refs": list(doc.get("data_model_references") or []),
        "url": ANALYTIC_URL.format(id=doc["id"]),
        "raw": json.loads(json.dumps(doc, default=str)),
    }
    best = {}
    for entry in doc.get("coverage") or []:
        tactics = entry.get("tactics") or []
        for technique in [entry["technique"], *(entry.get("subtechniques") or [])]:
            row = {
                "analytic_id": doc["id"],
                "technique_id": technique,
                "tactic_id": tactics[0] if len(tactics) == 1 else None,
                "coverage": entry.get("coverage"),
            }
            old = best.get(technique)
            rank = lambda r: COVERAGE_RANK.get(
                (r["coverage"] or "").lower(), 0
            )  # noqa: E731
            if old is None or rank(row) > rank(old):
                best[technique] = row
    return analytic, list(best.values())


def read_analytics(directory):
    """
    Parse every ``analytics/*.yaml`` under a CAR checkout, sorted by id.

    :rtype: list[tuple[dict, list[dict]]]
    """
    files = sorted((Path(directory) / "analytics").glob("*.yaml"))
    if not files:
        raise RuntimeError(f"no analytics found under {directory}/analytics")
    return sorted(
        (parse_analytic(yaml.safe_load(f.read_text())) for f in files),
        key=lambda a: a[0]["id"],
    )


def load(conn, parsed):
    """
    Upsert analytics and their technique coverage; analytics no longer in the repo are removed.

    :return: ``{"analytics": n, "technique_links": n, "removed": n}``
    :rtype: dict
    """
    ensure_source(conn, SOURCE)
    ids = [a["id"] for a, _ in parsed]
    removed = conn.execute(
        "DELETE FROM pivot.analytic WHERE repo = 'car' AND NOT (id = ANY(%s))", (ids,)
    ).rowcount
    links = 0
    for analytic, techniques in parsed:
        conn.execute(
            "INSERT INTO pivot.analytic (id, repo, title, information_domain, platforms, data_model_refs, "
            "url, raw, synced_at) VALUES (%(id)s, 'car', %(title)s, %(information_domain)s, %(platforms)s, "
            "%(data_model_refs)s, %(url)s, %(raw)s, now()) ON CONFLICT (id) DO UPDATE SET "
            "title = EXCLUDED.title, information_domain = EXCLUDED.information_domain, "
            "platforms = EXCLUDED.platforms, data_model_refs = EXCLUDED.data_model_refs, "
            "url = EXCLUDED.url, raw = EXCLUDED.raw, synced_at = now()",
            {**analytic, "raw": Jsonb(analytic["raw"])},
        )
        conn.execute(
            "DELETE FROM pivot.analytic_technique WHERE analytic_id = %s",
            (analytic["id"],),
        )
        for t in techniques:
            conn.execute(
                "INSERT INTO pivot.analytic_technique (analytic_id, technique_id, tactic_id, coverage) "
                "VALUES (%(analytic_id)s, %(technique_id)s, %(tactic_id)s, %(coverage)s)",
                t,
            )
            links += 1
    conn.commit()
    return {"analytics": len(parsed), "technique_links": links, "removed": removed}


def normalized_links(conn, attack_version):
    """
    Analytic→technique links mapped to ``attack_version`` through revoked-by chains (SPEC §5.4).

    CAR lags ATT&CK releases (v20 renumbered the Impair Defenses family, T1562 -> T1685), so the
    stored IDs are as declared by CAR and are mapped here. Links that map to the same
    technique/analytic pair keep the strongest coverage; unmappable IDs are dropped.

    :return: ``(links, unmapped)`` where each link has ``technique_id``, ``analytic_id``,
        ``coverage`` and ``declared_id``, and ``unmapped`` lists the dropped declared IDs.
    :rtype: tuple[list[dict], list[str]]
    """
    index = attack.load_index(conn, attack_version)
    rows = conn.execute(
        "SELECT analytic_id, technique_id, coverage FROM pivot.analytic_technique "
        "ORDER BY analytic_id, technique_id"
    ).fetchall()
    best, unmapped = {}, set()
    rank = lambda c: COVERAGE_RANK.get((c or "").lower(), 0)  # noqa: E731
    for r in rows:
        technique, _ = attack.normalize_technique(r["technique_id"], index)
        if technique is None:
            unmapped.add(r["technique_id"])
            continue
        key = (r["analytic_id"], technique)
        if key not in best or rank(r["coverage"]) > rank(best[key]["coverage"]):
            best[key] = {
                "analytic_id": r["analytic_id"],
                "technique_id": technique,
                "coverage": r["coverage"],
                "declared_id": r["technique_id"],
            }
    return list(best.values()), sorted(unmapped)


def baseline_layer(conn, attack_version):
    """
    Build the "CAR baseline" ATT&CK Navigator layer (layer format 4.5): a technique is covered
    when at least one analytic lists it, after mapping CAR's IDs to ``attack_version``. Colour
    and comments follow CAR's own generated layer.

    :param str attack_version: ATT&CK version to map to; its major number goes in the header.
    :rtype: dict
    """
    links, _ = normalized_links(conn, attack_version)
    titles = {
        r["id"]: r["title"] or ""
        for r in conn.execute("SELECT id, title FROM pivot.analytic")
    }
    names = {}
    for link in links:
        names.setdefault(link["technique_id"], set()).add(
            f"{link['analytic_id']}: {titles[link['analytic_id']]}"
        )
    techniques = []
    for technique_id in sorted(names):
        entry = {
            "techniqueID": technique_id,
            "color": "#c6dbef",
            "comment": " | ".join(sorted(names[technique_id])),
            "enabled": True,
        }
        if "." not in technique_id:
            entry["showSubtechniques"] = True
        techniques.append(entry)
    return {
        "versions": {
            "layer": "4.5",
            "attack": attack_version.split(".")[0],
            "navigator": "5.1.0",
        },
        "name": LAYER_NAME,
        "description": "Techniques with at least one MITRE CAR analytic",
        "domain": "enterprise-attack",
        "techniques": techniques,
    }


def store_baseline(conn, layer, attack_version):
    """Save the baseline as the built-in ``coverage_layer`` (replacing the previous copy)."""
    conn.execute("DELETE FROM pivot.coverage_layer WHERE name = %s", (LAYER_NAME,))
    layer_id = conn.execute(
        "INSERT INTO pivot.coverage_layer (name, navigator, attack_version, imported_at) "
        "VALUES (%s, %s, %s, now()) RETURNING id",
        (LAYER_NAME, Jsonb(layer), attack_version),
    ).fetchone()["id"]
    for t in layer["techniques"]:
        conn.execute(
            "INSERT INTO pivot.coverage_item (layer_id, technique_id, covered) VALUES (%s, %s, true)",
            (layer_id, t["techniqueID"]),
        )
    conn.commit()
    return layer_id
