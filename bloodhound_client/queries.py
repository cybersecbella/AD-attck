"""
Cypher query library.

Phase 1: just enough to prove the pipeline works end-to-end —
shortest paths from any non-privileged principal to Domain Admins.

Phase 3 will expand this into the full "top 10 dangerous paths"
scoring logic (path length + tier-0 proximity + node count).
"""

# Shortest paths to any group named "DOMAIN ADMINS@..." — adjust the
# name filter per-domain, or parameterize later once multi-domain
# support is needed.
SHORTEST_PATH_TO_DA = """
MATCH (n),(g:Group)
WHERE g.name STARTS WITH 'DOMAIN ADMINS@'
  AND n <> g
MATCH p = shortestPath((n)-[*1..]->(g))
RETURN p
LIMIT 25
"""

# Sanity-check query: confirms the DB has data at all before running
# anything complex. Useful as a first smoke test against a fresh
# BloodHound ingest.
COUNT_ALL_USERS = """
MATCH (u:User)
RETURN count(u) AS user_count
"""

# Kerberoastable accounts — used later by kerberoast_detector, but
# defined here since it's a BloodHound graph property (hasspn),
# not something impacket/LDAP needs to derive independently.
KERBEROASTABLE_USERS = """
MATCH (u:User)
WHERE u.hasspn = true
RETURN u.name AS name, u.enabled AS enabled, u.pwdlastset AS pwdlastset
"""
