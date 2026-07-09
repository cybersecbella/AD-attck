"""
Basic severity scoring for BloodHound attack path edges/chains.

This is intentionally simple for Phase 3 -- a real scoring model would
weigh tier-0 proximity, node exposure (session counts, local admin
reach), and more edge types. This gives a defensible first pass:
dangerous edge kinds score higher, and shorter chains to a privileged
target score higher than long ones (fewer steps = easier for an
attacker to execute in practice).
"""

from bloodhound_client.models import AttackPath

# Edge weights -- higher means more directly dangerous. Values are
# illustrative, not derived from a formal risk model; tune per-environment
# once you have real path data to calibrate against.
EDGE_WEIGHTS = {
    "GENERICALL": 9,
    "GENERICWRITE": 8,
    "WRITEDACL": 9,
    "WRITEOWNER": 8,
    "OWNS": 7,
    "FORCECHANGEPASSWORD": 7,
    "ADDMEMBER": 6,
    "ALLEXTENDEDRIGHTS": 8,
    "ADCSESC1": 10,
    "ADCSESC4": 10,
    "MEMBEROF": 3,
    "ADMINTO": 6,
    "HASSESSION": 4,
    "CANRDP": 3,
    "SQLADMIN": 5,
}
DEFAULT_EDGE_WEIGHT = 2  # unrecognized edge kinds still count, just conservatively


def score_edge(edge: AttackPath) -> int:
    kind = (edge.raw.get("kind") or "").upper()
    return EDGE_WEIGHTS.get(kind, DEFAULT_EDGE_WEIGHT)


def score_path_chain(edges: list[AttackPath]) -> dict:
    """
    Scores a full chain of edges (start -> ... -> end) as a single path.

    Returns:
        {
            "total_edge_score": int,
            "hop_count": int,
            "severity_score": int,   # final score, higher = more dangerous
            "edge_kinds": [...]
        }
    """
    if not edges:
        return {"total_edge_score": 0, "hop_count": 0, "severity_score": 0, "edge_kinds": []}

    total_edge_score = sum(score_edge(e) for e in edges)
    hop_count = len(edges)

    # Mild penalty per extra hop beyond the first -- a 1-hop GenericAll
    # straight to Domain Admins is more urgent than the same edge type
    # buried 4 hops deep in a chain that also requires other conditions.
    hop_penalty = max(0, hop_count - 1)
    severity_score = max(0, total_edge_score - hop_penalty)

    return {
        "total_edge_score": total_edge_score,
        "hop_count": hop_count,
        "severity_score": severity_score,
        "edge_kinds": [e.raw.get("kind") for e in edges],
    }


def rank_paths(path_chains: list[list[AttackPath]], top_n: int = 10) -> list[dict]:
    """
    Scores and ranks multiple path chains, returning the top_n most
    severe. Each returned dict includes the score breakdown plus the
    original edge list for downstream use (correlator, narrator).
    """
    scored = []
    for chain in path_chains:
        result = score_path_chain(chain)
        result["path"] = chain
        scored.append(result)

    scored.sort(key=lambda r: r["severity_score"], reverse=True)
    return scored[:top_n]
