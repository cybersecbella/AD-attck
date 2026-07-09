"""
Phase 3 test suite for bloodhound_client/scoring.py.

Run with:
    python -m pytest tests/test_scoring.py -v
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bloodhound_client.models import parse_path_response
from bloodhound_client.scoring import score_edge, score_path_chain, rank_paths

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "sample_path_response.json"
)


def load_paths():
    with open(FIXTURE_PATH) as f:
        return parse_path_response(json.load(f))


def test_score_edge_recognizes_dangerous_kind():
    paths = load_paths()
    generic_all_edge = paths[0]  # bob -> helpdesk_svc, GenericAll
    assert score_edge(generic_all_edge) == 9


def test_score_edge_recognizes_low_risk_kind():
    paths = load_paths()
    member_of_edge = paths[1]  # helpdesk_svc -> DOMAIN ADMINS, MemberOf
    assert score_edge(member_of_edge) == 3


def test_score_edge_unrecognized_kind_gets_default():
    from bloodhound_client.models import AttackPath
    edge = AttackPath(start_node="a", end_node="b", hop_count=1, raw={"kind": "SomeNewEdgeType"})
    assert score_edge(edge) == 2  # DEFAULT_EDGE_WEIGHT


def test_score_path_chain_combines_both_edges():
    paths = load_paths()  # 2-edge chain: GenericAll (9) + MemberOf (3)
    result = score_path_chain(paths)

    assert result["total_edge_score"] == 12
    assert result["hop_count"] == 2
    # hop_penalty = hop_count - 1 = 1, so severity = 12 - 1 = 11
    assert result["severity_score"] == 11
    assert result["edge_kinds"] == ["GenericAll", "MemberOf"]


def test_score_path_chain_empty_list():
    result = score_path_chain([])
    assert result["severity_score"] == 0
    assert result["hop_count"] == 0


def test_rank_paths_sorts_by_severity_descending():
    paths = load_paths()
    single_edge_chain = [paths[0]]  # just GenericAll, score 9
    full_chain = paths  # GenericAll + MemberOf, score 11

    ranked = rank_paths([single_edge_chain, full_chain], top_n=10)

    assert ranked[0]["severity_score"] == 11
    assert ranked[1]["severity_score"] == 9


def test_rank_paths_respects_top_n():
    paths = load_paths()
    chains = [[paths[0]]] * 15  # 15 identical single-edge chains

    ranked = rank_paths(chains, top_n=5)

    assert len(ranked) == 5


if __name__ == "__main__":
    test_score_edge_recognizes_dangerous_kind()
    test_score_edge_recognizes_low_risk_kind()
    test_score_edge_unrecognized_kind_gets_default()
    test_score_path_chain_combines_both_edges()
    test_score_path_chain_empty_list()
    test_rank_paths_sorts_by_severity_descending()
    test_rank_paths_respects_top_n()
    print("All Phase 3 scoring tests passed.")
