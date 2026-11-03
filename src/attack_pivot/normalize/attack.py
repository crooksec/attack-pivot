"""ATT&CK Enterprise STIX: parsing, loading and technique-ID normalization."""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
USER_AGENT = "attack-pivot/0.1 (+https://github.com/crooksec/attack-pivot)"


@dataclass
class AttackData:
    """The parts of one ATT&CK Enterprise release that the pivot database stores."""

    version: str
    released: str | None = None
    tactics: list[dict] = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    replacements: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def parse_bundle(bundle, version):
    """
    Parse an ATT&CK Enterprise STIX bundle.

    Tactic order comes from the matrix object's ``tactic_refs``. A technique's tactics come
    from its ``mitre-attack`` kill chain phases. ``revoked-by`` relationships become
    replacement rows keyed by ATT&CK ID.

    :param dict bundle: Parsed STIX bundle JSON.
    :param str version: ATT&CK version label, e.g. ``"20.0"``.
    :rtype: AttackData
    """
    objects = bundle.get("objects", [])
    by_stix_id = {o["id"]: o for o in objects if "id" in o}
    data = AttackData(version=version)

    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            data.released = (obj.get("modified") or obj.get("created") or "")[
                :10
            ] or None

    order = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-matrix":
            for i, ref in enumerate(obj.get("tactic_refs", [])):
                order.setdefault(ref, i + 1)

    shortname_to_tactic = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked"):
            continue
        attack_id = _attack_id(obj)
        if not attack_id:
            continue
        shortname = obj.get("x_mitre_shortname")
        shortname_to_tactic[shortname] = attack_id
        data.tactics.append(
            {
                "attack_id": attack_id,
                "name": obj["name"],
                "shortname": shortname,
                "ord": order.get(obj["id"]),
            }
        )
    data.tactics.sort(key=lambda t: (t["ord"] is None, t["ord"] or 0, t["attack_id"]))

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        attack_id = _attack_id(obj)
        if not attack_id or not re.fullmatch(r"T\d{4}(\.\d{3})?", attack_id):
            continue
        phases = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        data.techniques.append(
            {
                "attack_id": attack_id,
                "name": obj["name"],
                "parent_id": attack_id.split(".")[0] if "." in attack_id else None,
                "tactic_ids": [
                    shortname_to_tactic[p] for p in phases if p in shortname_to_tactic
                ],
                "platforms": obj.get("x_mitre_platforms", []),
                "revoked": bool(obj.get("revoked")),
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "stix_id": obj["id"],
            }
        )

    for obj in objects:
        if (
            obj.get("type") != "relationship"
            or obj.get("relationship_type") != "revoked-by"
        ):
            continue
        src, dst = by_stix_id.get(obj["source_ref"]), by_stix_id.get(obj["target_ref"])
        if not src or not dst or src.get("type") != "attack-pattern":
            continue
        from_id, to_id = _attack_id(src), _attack_id(dst)
        if from_id and to_id:
            data.replacements.append(
                {"from_id": from_id, "to_id": to_id, "relation": "revoked-by"}
            )

    for obj in objects:
        if obj.get("type") != "intrusion-set" or obj.get("revoked"):
            continue
        group_id = _attack_id(obj)
        if group_id:
            aliases = list(dict.fromkeys([obj["name"], *obj.get("aliases", [])]))
            data.groups.append(
                {"attack_group_id": group_id, "name": obj["name"], "aliases": aliases}
            )
    return data


def data_dir():
    """Directory for downloaded ATT&CK files (``DATA_DIR``/pivot/attack)."""
    return Path(os.environ.get("DATA_DIR", "data")) / "pivot" / "attack"


def fetch_bundle(version, cache_dir=None):
    """
    Return the parsed STIX bundle for a version, downloading it once into the cache.

    :param str version:
    :param Path cache_dir: Defaults to :func:`data_dir`.
    :rtype: dict
    """
    cache_dir = Path(cache_dir) if cache_dir else data_dir()
    path = cache_dir / f"enterprise-attack-{version}.json"
    if not path.exists():
        url = STIX_URL.format(version=version)
        logger.info("downloading %s", url)
        response = httpx.get(
            url, headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=120
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"could not download ATT&CK {version}: HTTP {response.status_code}"
            )
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_bytes(response.content)
    return json.loads(path.read_text())


def load(conn, data, stix_url=None):
    """
    Upsert one ATT&CK release (version, tactics, techniques, replacements, groups, aliases).

    :param psycopg.Connection conn:
    :param AttackData data:
    :return: Row counts by table.
    :rtype: dict
    """
    v = data.version
    conn.execute(
        "INSERT INTO pivot.attack_version (version, released, stix_url, synced_at) "
        "VALUES (%s, %s, %s, now()) ON CONFLICT (version) DO UPDATE SET "
        "released = EXCLUDED.released, stix_url = EXCLUDED.stix_url, synced_at = now()",
        (v, data.released, stix_url),
    )
    for t in data.tactics:
        conn.execute(
            "INSERT INTO pivot.tactic (attack_id, version, name, shortname, ord) "
            "VALUES (%(attack_id)s, %(v)s, %(name)s, %(shortname)s, %(ord)s) "
            "ON CONFLICT (attack_id, version) DO UPDATE SET name = EXCLUDED.name, "
            "shortname = EXCLUDED.shortname, ord = EXCLUDED.ord",
            {**t, "v": v},
        )
    for t in data.techniques:
        conn.execute(
            "INSERT INTO pivot.technique (attack_id, version, name, parent_id, tactic_ids, "
            "platforms, revoked, deprecated, stix_id) VALUES (%(attack_id)s, %(v)s, %(name)s, "
            "%(parent_id)s, %(tactic_ids)s, %(platforms)s, %(revoked)s, %(deprecated)s, %(stix_id)s) "
            "ON CONFLICT (attack_id, version) DO UPDATE SET name = EXCLUDED.name, "
            "parent_id = EXCLUDED.parent_id, tactic_ids = EXCLUDED.tactic_ids, "
            "platforms = EXCLUDED.platforms, revoked = EXCLUDED.revoked, "
            "deprecated = EXCLUDED.deprecated, stix_id = EXCLUDED.stix_id",
            {**t, "v": v},
        )
    for r in data.replacements:
        conn.execute(
            "INSERT INTO pivot.technique_replacement (from_id, to_id, version, relation) "
            "VALUES (%(from_id)s, %(to_id)s, %(v)s, %(relation)s) ON CONFLICT DO NOTHING",
            {**r, "v": v},
        )
    for g in data.groups:
        actor_id = conn.execute(
            "INSERT INTO pivot.actor (attack_group_id, name) VALUES (%s, %s) "
            "ON CONFLICT (attack_group_id) DO UPDATE SET name = EXCLUDED.name RETURNING id",
            (g["attack_group_id"], g["name"]),
        ).fetchone()["id"]
        for alias in g["aliases"]:
            conn.execute(
                "INSERT INTO pivot.actor_alias (actor_id, alias, source) VALUES (%s, %s, 'attack') "
                "ON CONFLICT DO NOTHING",
                (actor_id, alias),
            )
    conn.commit()
    return {
        "tactics": len(data.tactics),
        "techniques": len(data.techniques),
        "replacements": len(data.replacements),
        "groups": len(data.groups),
    }


@dataclass
class TechniqueIndex:
    """Valid technique IDs and revoked-by chains for one ATT&CK version."""

    valid: set[str]
    replaced_by: dict[str, str]


def load_index(conn, version):
    """
    Build a :class:`TechniqueIndex` from the database.

    :param psycopg.Connection conn:
    :param str version:
    :rtype: TechniqueIndex
    """
    rows = conn.execute(
        "SELECT attack_id FROM pivot.technique WHERE version = %s AND NOT revoked AND NOT deprecated",
        (version,),
    ).fetchall()
    repl = conn.execute(
        "SELECT from_id, to_id FROM pivot.technique_replacement WHERE version = %s",
        (version,),
    ).fetchall()
    return TechniqueIndex(
        {r["attack_id"] for r in rows}, {r["from_id"]: r["to_id"] for r in repl}
    )


def normalize_technique(technique_id, index):
    """
    Map a technique ID to its current form by following ``revoked-by`` chains.

    :param str technique_id: As extracted, e.g. ``"T1086"``.
    :param TechniqueIndex index:
    :return: ``(normalized_id or None, chain)``. ``None`` means unmappable (log and drop).
    :rtype: tuple[str | None, list[str]]
    """
    chain = [technique_id]
    current = technique_id
    while current not in index.valid:
        nxt = index.replaced_by.get(current)
        if nxt is None or nxt in chain:  # no replacement, or a cycle
            logger.warning("technique %s is unmappable (chain %s)", technique_id, chain)
            return None, chain
        chain.append(nxt)
        current = nxt
    return current, chain
