"""
Hardening recommendation engine.

Takes edge kinds (from a BloodHound path) and/or an evidence type
(from the correlator) and returns concrete, actionable recommendations
by looking them up in mappings.yaml.

Kept as simple lookup logic on purpose -- no scoring or prioritization
here, that's scoring.py's job. This module just answers "what do I do
about this."
"""

import os
import yaml

DEFAULT_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "mappings.yaml")

_cache = None


def load_mappings(path: str = DEFAULT_MAPPINGS_PATH) -> dict:
    global _cache
    if _cache is None:
        with open(path) as f:
            _cache = yaml.safe_load(f)
    return _cache


def get_edge_recommendations(edge_kinds: list[str], path: str = DEFAULT_MAPPINGS_PATH) -> list[str]:
    """
    Returns deduplicated recommendations for a list of edge kinds,
    preserving first-seen order. Unrecognized edge kinds are silently
    skipped (not every edge type has -- or needs -- a canned recommendation).
    """
    mappings = load_mappings(path).get("edge_recommendations", {})
    seen = set()
    recommendations = []

    for kind in edge_kinds:
        if not kind or kind in seen:
            continue
        rec = mappings.get(kind)
        if rec:
            recommendations.append(rec.strip())
            seen.add(kind)

    return recommendations


def get_evidence_recommendation(evidence_type: str | None, path: str = DEFAULT_MAPPINGS_PATH) -> str | None:
    """Returns the single recommendation tied to a correlator evidence type, if any."""
    if not evidence_type:
        return None
    mappings = load_mappings(path).get("evidence_recommendations", {})
    rec = mappings.get(evidence_type)
    return rec.strip() if rec else None


def build_recommendations(
    edge_kinds: list[str], evidence_type: str | None = None, path: str = DEFAULT_MAPPINGS_PATH
) -> list[str]:
    """
    Combines evidence-driven and edge-driven recommendations into one
    ordered list. Evidence-driven recs come first -- if there's active
    exploitation evidence, that's the most urgent action regardless of
    which ACL misconfiguration enabled the path in the first place.
    """
    recommendations = []

    evidence_rec = get_evidence_recommendation(evidence_type, path)
    if evidence_rec:
        recommendations.append(evidence_rec)

    recommendations.extend(get_edge_recommendations(edge_kinds, path))

    return recommendations
