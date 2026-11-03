"""Technique/tactic hierarchy of one ATT&CK version, used to roll states up."""

from dataclasses import dataclass, field

START = "START"
END = "END"
LEVELS = ("subtechnique", "technique", "tactic")


@dataclass
class Taxonomy:
    """
    Parent and tactic lookups for the pinned ATT&CK version.

    Tactics come from this version's technique table, not from a flow's ``tactic_id``: flows
    were authored against older taxonomies (v20 split Defense Evasion into Stealth and
    Defense Impairment), so the version table is the one consistent source.
    """

    version: str
    parent: dict[str, str | None] = field(default_factory=dict)
    tactics: dict[str, list[str]] = field(default_factory=dict)
    tactic_order: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, conn, version):
        """Read valid (non-revoked, non-deprecated) techniques and the tactics of ``version``."""
        techniques = conn.execute(
            "SELECT attack_id, parent_id, tactic_ids FROM pivot.technique "
            "WHERE version = %s AND NOT revoked AND NOT deprecated",
            (version,),
        ).fetchall()
        tactics = conn.execute(
            "SELECT attack_id, ord FROM pivot.tactic WHERE version = %s", (version,)
        ).fetchall()
        if not techniques:
            raise RuntimeError(
                f"ATT&CK {version} is not in the database; run `afp attack sync`"
            )
        return cls(
            version=version,
            parent={t["attack_id"]: t["parent_id"] for t in techniques},
            tactics={t["attack_id"]: list(t["tactic_ids"] or []) for t in techniques},
            tactic_order={t["attack_id"]: t["ord"] for t in tactics},
        )

    def states(self, level, technique_id, tactic_id=None):
        """
        The state(s) of an action at ``level`` with their weights.

        A technique in k tactics yields k tactic states of weight 1/k (SPEC §7.1). An action with
        no technique but a known tactic is a tactic-level state only.

        :return: ``[(state, weight), ...]``, empty if the action has no state at this level.
        :rtype: list[tuple[str, float]]
        """
        if technique_id and technique_id in self.parent:
            if level == "subtechnique":
                return [(technique_id, 1.0)]
            if level == "technique":
                return [(self.parent[technique_id] or technique_id, 1.0)]
            tactics = self.tactics.get(technique_id) or []
            return [(t, 1.0 / len(tactics)) for t in tactics]
        if level == "tactic" and not technique_id and tactic_id in self.tactic_order:
            return [(tactic_id, 1.0)]
        return []

    def technique_parent(self, technique_id):
        """The technique-level state of an ID (a sub-technique's parent, else itself)."""
        return self.parent.get(technique_id) or technique_id

    def vocabulary(self, level):
        """
        The ordered destination states at ``level`` (without ``END``): every valid
        sub-technique/technique ID, every base technique, or every tactic.

        :rtype: list[str]
        """
        if level == "subtechnique":
            return sorted(self.parent)
        if level == "technique":
            return sorted(t for t, p in self.parent.items() if p is None)
        return sorted(self.tactic_order, key=lambda t: (self.tactic_order[t], t))
