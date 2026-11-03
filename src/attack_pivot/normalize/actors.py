"""Threat-actor name normalization to ATT&CK groups (SPEC §5.4)."""

from rapidfuzz import fuzz, process

FUZZY_THRESHOLD = 92


def _key(name):
    return " ".join(name.lower().split())


def load_aliases(conn):
    """
    Alias index from the ``actor_alias`` table.

    :return: ``{normalized alias: (actor_id, alias)}``
    :rtype: dict
    """
    rows = conn.execute("SELECT actor_id, alias FROM pivot.actor_alias").fetchall()
    return {_key(r["alias"]): (r["actor_id"], r["alias"]) for r in rows}


def match_actor(name, aliases):
    """
    Resolve a name against the alias index: exact first, then ``rapidfuzz`` >= 92.

    :param str name:
    :param dict aliases: From :func:`load_aliases`.
    :return: ``(actor_id, basis, confidence)``; ``actor_id`` is ``None`` when unmatched.
        Fuzzy matches carry ``basis='alias_fuzzy:<score>:<alias>'`` and stay unconfirmed
        (``attribution_confidence`` 0.5): they are the manual-confirm queue.
    :rtype: tuple
    """
    key = _key(name)
    if key in aliases:
        return aliases[key][0], "alias_exact", 1.0
    if aliases:
        hit = process.extractOne(
            key, aliases.keys(), scorer=fuzz.ratio, score_cutoff=FUZZY_THRESHOLD
        )
        if hit:
            matched, score, _ = hit
            return (
                aliases[matched][0],
                f"alias_fuzzy:{score:.0f}:{aliases[matched][1]}",
                0.5,
            )
    return None, "unmatched", None
