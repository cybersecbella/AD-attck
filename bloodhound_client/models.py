"""
Minimal data classes for representing BloodHound query results.
Kept intentionally small for Phase 1 — expand once the correlator
and narrator (Phase 3-4) need richer path metadata (severity score,
tier-0 flags, etc).
"""

from dataclasses import dataclass, field


@dataclass
class AttackPath:
    start_node: str
    end_node: str
    hop_count: int
    raw: dict = field(default_factory=dict)  # full Cypher result, for later use

    def __repr__(self):
        return f"<AttackPath {self.start_node} -> {self.end_node} ({self.hop_count} hops)>"


@dataclass
class KerberoastableAccount:
    name: str
    enabled: bool
    password_last_set: str | None = None


def parse_path_response(raw: dict) -> list[AttackPath]:
    """
    Converts a raw BloodHound CE /api/v2/graphs/cypher response (nodes + edges)
    into a flat list of AttackPath objects, one per edge in the path.

    This is intentionally simple for Phase 1 -- it does not attempt to
    reconstruct multi-hop path ordering or severity scoring yet (that's
    Phase 3). It just proves we can turn the graph shape into something
    usable in Python.
    """
    nodes = raw.get("data", {}).get("nodes", {})
    edges = raw.get("data", {}).get("edges", [])

    paths = []
    for edge in edges:
        source_node = nodes.get(edge["source"], {})
        target_node = nodes.get(edge["target"], {})

        paths.append(
            AttackPath(
                start_node=source_node.get("label", "UNKNOWN"),
                end_node=target_node.get("label", "UNKNOWN"),
                hop_count=1,  # per-edge hop count; multi-hop aggregation comes in Phase 3
                raw=edge,
            )
        )

    return paths
