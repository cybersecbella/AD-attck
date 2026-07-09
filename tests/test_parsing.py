"""
Phase 1 fixture test -- no live BloodHound instance required.

Loads a static JSON fixture (modeled on a real BloodHound CE Cypher
response) and validates that parse_path_response() correctly turns it
into AttackPath objects. This is the "80% confidence, no lab setup"
sanity check before touching Docker or a live instance.

Run with:
    python -m pytest tests/test_parsing.py -v
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bloodhound_client.models import parse_path_response, AttackPath

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "sample_path_response.json")


def load_fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_fixture_loads():
    data = load_fixture()
    assert "data" in data
    assert "nodes" in data["data"]
    assert "edges" in data["data"]


def test_parse_path_response_returns_attack_paths():
    data = load_fixture()
    paths = parse_path_response(data)

    assert len(paths) == 2
    assert all(isinstance(p, AttackPath) for p in paths)


def test_parse_path_response_resolves_labels_correctly():
    data = load_fixture()
    paths = parse_path_response(data)

    # First edge: bob -> helpdesk_svc via GenericAll
    assert paths[0].start_node == "bob@phantom.corp"
    assert paths[0].end_node == "helpdesk_svc@phantom.corp"
    assert paths[0].raw["kind"] == "GenericAll"

    # Second edge: helpdesk_svc -> DOMAIN ADMINS via MemberOf
    assert paths[1].start_node == "helpdesk_svc@phantom.corp"
    assert paths[1].end_node == "DOMAIN ADMINS@PHANTOM.CORP"
    assert paths[1].raw["kind"] == "MemberOf"


def test_parse_path_response_handles_missing_nodes_gracefully():
    broken_data = {
        "data": {
            "nodes": {},
            "edges": [{"source": "99", "target": "100", "kind": "GenericAll"}],
        }
    }
    paths = parse_path_response(broken_data)

    assert len(paths) == 1
    assert paths[0].start_node == "UNKNOWN"
    assert paths[0].end_node == "UNKNOWN"


if __name__ == "__main__":
    test_fixture_loads()
    test_parse_path_response_returns_attack_paths()
    test_parse_path_response_resolves_labels_correctly()
    test_parse_path_response_handles_missing_nodes_gracefully()
    print("All fixture tests passed.")
