"""
BloodHound CE REST API client.

BloodHound CE signs requests with HMAC-SHA256 over the API key,
using a scheme documented at:
https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api

If you're on legacy BloodHound (no REST API, Neo4j-only), see
bloodhound_client/neo4j_client.py instead (Phase 1 stub, not yet built).
"""

import base64
import datetime
import hmac
import hashlib
import requests


class BloodHoundAPIError(Exception):
    pass


class BloodHoundClient:
    def __init__(self, base_url: str, api_id: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_id = api_id
        self.api_key = api_key

    def _signed_headers(self, method: str, uri: str, body: bytes = b"") -> dict:
        """
        Builds the HMAC signature BloodHound CE expects:
        1. HMAC(key, METHOD + URI)
        2. HMAC(step1_digest, RFC3339 datetime truncated to the hour)
        3. HMAC(step2_digest, request body)
        """
        datetime_formatted = datetime.datetime.now(datetime.timezone.utc).isoformat("T", "seconds")

        digester = hmac.new(self.api_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{uri}".encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        digester.update(datetime_formatted[:13].encode())  # truncate to the hour
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body:
            digester.update(body)

        signature = base64.b64encode(digester.digest())

        return {
            "Authorization": f"bhesignature {self.api_id}",
            "RequestDate": datetime_formatted,
            "Signature": signature.decode(),
            "Content-Type": "application/json",
        }

    def _request(self, method: str, uri: str, body: bytes = b"") -> dict:
        headers = self._signed_headers(method, uri, body)
        url = f"{self.base_url}{uri}"

        resp = requests.request(method, url, headers=headers, data=body, timeout=30)

        if resp.status_code >= 400:
            raise BloodHoundAPIError(
                f"{method} {uri} failed: {resp.status_code} {resp.text}"
            )

        return resp.json()

    def test_connection(self) -> bool:
        """
        Auth + connectivity check.

        NOTE: earlier BloodHound CE versions exposed /api/version unauthenticated,
        but current versions require a signed request even for this. We hit
        /api/v2/self instead (returns the authenticated user's own profile),
        which both confirms the server is reachable AND that our HMAC signing
        and credentials are correct.
        """
        try:
            self._request("GET", "/api/v2/self")
            return True
        except BloodHoundAPIError as e:
            msg = str(e)
            if "401" in msg:
                raise BloodHoundAPIError(
                    "Got 401 Unauthorized. This usually means api_id/api_key in "
                    "config.yaml are wrong or swapped (api_key should be the "
                    "'Token Key', not the 'Token ID'). Regenerate the token in "
                    "Administration > Manage Users > Generate/Revoke API Tokens "
                    "if you're not sure, since the key is only shown once."
                ) from e
            raise

    def run_cypher(self, query: str) -> dict:
        """Runs a raw Cypher query against BloodHound CE's /api/v2/graphs/cypher endpoint."""
        import json
        body = json.dumps({"query": query, "include_properties": True}).encode()
        return self._request("POST", "/api/v2/graphs/cypher", body)
