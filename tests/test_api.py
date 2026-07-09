"""
Phase 1 unit test — doesn't require a live BloodHound server.
Just confirms the HMAC signing logic runs without errors and
produces headers of the expected shape. Run with:

    python -m pytest tests/test_api.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bloodhound_client.api import BloodHoundClient


def test_signed_headers_structure():
    client = BloodHoundClient(
        base_url="http://localhost:8080",
        api_id="fake-id",
        api_key="fake-key",
    )
    headers = client._signed_headers("GET", "/api/v2/graphs/cypher")

    assert "Authorization" in headers
    assert headers["Authorization"] == "bhesignature fake-id"
    assert "RequestDate" in headers
    assert "Signature" in headers
    assert headers["Content-Type"] == "application/json"
    assert len(headers["Signature"]) > 0


def test_signed_headers_change_with_body():
    client = BloodHoundClient(
        base_url="http://localhost:8080",
        api_id="fake-id",
        api_key="fake-key",
    )
    headers_no_body = client._signed_headers("POST", "/api/v2/graphs/cypher")
    headers_with_body = client._signed_headers(
        "POST", "/api/v2/graphs/cypher", body=b'{"query": "MATCH (n) RETURN n"}'
    )

    # Signature should differ once a body is included
    assert headers_no_body["Signature"] != headers_with_body["Signature"]


if __name__ == "__main__":
    test_signed_headers_structure()
    test_signed_headers_change_with_body()
    print("All Phase 1 tests passed.")