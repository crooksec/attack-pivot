"""Cheap first-pass triage: ATT&CK IDs, behaviour vocabulary and sequence language (SPEC §6.3)."""

import re

from attack_pivot.normalize import attack

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Attacker-behaviour vocabulary, grouped by rough lifecycle phase. A report that touches several
# groups is describing an intrusion rather than a single vulnerability or product.
BEHAVIOUR = {
    "access": r"phish|spear-?phish|initial access|exploited|exploitation of|brute[- ]force|valid accounts|vpn|rdp",
    "execution": r"powershell|cmd\.exe|wmic|rundll32|mshta|wscript|cscript|macro|command[- ]line|webshell",
    "persistence": r"persistence|run key|startup folder|scheduled task|new service|registry key|autorun",
    "privilege": r"privilege escalation|elevat|token (theft|impersonat)|uac bypass|sudo",
    "credentials": r"mimikatz|lsass|credential (dump|theft|access)|kerberoast|ntds|dcsync|password spray|hashdump",
    "discovery": r"nltest|adfind|bloodhound|net (view|group|user)|whoami|ipconfig|network scan|reconnaissance",
    "lateral": r"lateral movement|psexec|wmi\b|smb\b|remote desktop|pass[- ]the[- ](hash|ticket)",
    "c2": r"cobalt strike|beacon|command[- ]and[- ]control|\bc2\b|reverse shell|sliver|brute ratel",
    "exfil_impact": r"exfiltrat|rclone|mega\.nz|ransom|encrypt(ed|ion) (files|data)|wiper|data theft",
}
NARRATIVE = r"threat actor|the attacker|the adversary|we observed|intrusion|incident response|compromised|post-exploitation|kill chain"
SEQUENCE = re.compile(
    r"\b(then|afterwards?|subsequently|followed by|next|later|shortly after|within \d+ (?:minutes?|hours?|days?)"
    r"|\d+ (?:minutes?|hours?|days?) (?:later|after)|day \d+|timeline)\b|\bT\+\d+|\b\d{1,2}:\d{2}(?::\d{2})?\b",
    re.I,
)

MIN_CHARS = 1500
MIN_TECHNIQUES = 3  # SPEC §6.3
MIN_CATEGORIES = 3  # distinct behaviour groups needed to ask the LLM without cited IDs
SEQUENCE_HITS = 5


def technique_mentions(text, index):
    """
    Distinct ATT&CK technique IDs cited in the text, normalized to the pinned version (revoked
    IDs follow their replacement; unknown IDs such as ATLAS or other-domain IDs are dropped).

    :param attack.TechniqueIndex index:
    :rtype: set[str]
    """
    found = set()
    for raw in set(TECHNIQUE_ID.findall(text)):
        normalized, _ = attack.normalize_technique(raw, index)
        if normalized:
            found.add(normalized)
    return found


def analyze(text, index):
    """
    :return: Counts the triage decision and the stored record are built from.
    :rtype: dict
    """
    lowered = text.lower()
    categories = [k for k, pattern in BEHAVIOUR.items() if re.search(pattern, lowered)]
    mentions = technique_mentions(text, index)
    sequence_hits = len(SEQUENCE.findall(text))
    return {
        "chars": len(text),
        "technique_mentions": len(mentions),
        "techniques": sorted(mentions),
        "behaviour_categories": categories,
        "narrative_cues": len(re.findall(NARRATIVE, lowered)),
        "sequence_hits": sequence_hits,
        "sequence_heuristic": sequence_hits >= SEQUENCE_HITS,
    }


def first_pass(stats):
    """
    Whether a report is worth an LLM call.

    :return: ``(passes, reason)``
    """
    if stats["chars"] < MIN_CHARS:
        return False, "heuristic:too_short"
    if stats["technique_mentions"] >= MIN_TECHNIQUES:
        return True, "heuristic:cites_techniques"
    if (
        len(stats["behaviour_categories"]) >= MIN_CATEGORIES
        and stats["narrative_cues"] >= 1
    ):
        return True, "heuristic:behaviour_vocabulary"
    return False, "heuristic:no_intrusion_signal"
