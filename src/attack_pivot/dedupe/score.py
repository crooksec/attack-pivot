"""Pair scoring for incident dedupe (SPEC §5.5). Pure functions: no database."""

import re
from dataclasses import dataclass, field
from itertools import combinations

WINDOW_DAYS = 45
AUTO_LINK = 0.75
REVIEW = 0.5
JACCARD_MIN = 0.5
UNDATED_CAP = 0.74  # an undated incident can be queued for review but never auto-linked

# score = W_ACTOR * actor + W_DATE * date + W_SIM * similarity
W_ACTOR, W_DATE, W_SIM = 0.25, 0.20, 0.55
SIM_URL, SIM_TAG = (
    0.8,
    0.5,
)  # a shared cited URL / a shared sector or region, vs Jaccard as is
UNKNOWN_ACTORS = 0.3  # both unknown: allowed as a candidate, but a weak actor signal

URL = re.compile(r"https?://[^\s\"'<>\]\)]+")


@dataclass
class Features:
    id: str
    first: object = None  # date | None
    last: object = None
    actors: set = field(default_factory=set)
    techniques: set = field(default_factory=set)
    tags: set = field(default_factory=set)  # sectors and regions, lower-cased
    urls: set = field(
        default_factory=set
    )  # canonical URLs of the reports and their citations

    @property
    def dated(self):
        return self.first is not None and self.last is not None


def jaccard(a, b):
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def score_pair(a, b):
    """
    Score whether two incidents are the same intrusion.

    Candidates need the same actor (or both unknown), dates within 45 days, and at least one of a
    shared victim sector/region, technique Jaccard >= 0.5, or a shared cited URL.

    :return: ``(score, signals)``, or ``None`` if the pair is not a candidate.
    """
    shared_actors = a.actors & b.actors
    if not shared_actors and (a.actors or b.actors):
        return None
    if a.dated and b.dated:
        gap = max(0, (max(a.first, b.first) - min(a.last, b.last)).days)
        if gap > WINDOW_DAYS:
            return None
        date_score = 1 - gap / WINDOW_DAYS
    else:
        gap, date_score = None, 0.0
    jac = jaccard(a.techniques, b.techniques)
    shared_tags, shared_urls = a.tags & b.tags, a.urls & b.urls
    if jac < JACCARD_MIN and not shared_tags and not shared_urls:
        return None
    sim = max(
        jac if jac >= JACCARD_MIN else 0.0,
        SIM_URL if shared_urls else 0.0,
        SIM_TAG if shared_tags else 0.0,
    )
    actor_score = 1.0 if shared_actors else UNKNOWN_ACTORS
    score = W_ACTOR * actor_score + W_DATE * date_score + W_SIM * sim
    if not (a.dated and b.dated):
        score = min(score, UNDATED_CAP)
    return round(score, 4), {
        "actor": "shared" if shared_actors else "both_unknown",
        "gap_days": gap,
        "jaccard": round(jac, 3),
        "shared_tags": sorted(shared_tags)[:5],
        "shared_urls": sorted(shared_urls)[:3],
    }


def candidates(features):
    """All scored pairs at or above the review threshold: ``[(a_id, b_id, score, signals)]``."""
    out = []
    for a, b in combinations(sorted(features, key=lambda f: f.id), 2):
        result = score_pair(a, b)
        if result and result[0] >= REVIEW:
            out.append((a.id, b.id, *result))
    return out


def urls_in(value):
    """URLs found anywhere in a JSON-ish value (flow external references, report URLs)."""
    return set(URL.findall(str(value)))
