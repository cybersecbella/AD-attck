"""
End-to-end pipeline demo -- runs Phases 1-4 together against the fixture
data used throughout the test suite, so you can see the whole thing work
as one flow before wiring it up against a live BloodHound/lab environment.

This intentionally uses fixtures instead of live connections so it runs
anywhere, with no Docker/lab/API key required for the first four steps.
Step 5 (narrator) will attempt a real Claude API call if a key is present
in config.yaml; otherwise it prints the prompt that would have been sent,
so you can still see what the pipeline produces.

Run with:
    python run_pipeline_demo.py
"""

import json
import os

from bloodhound_client.models import parse_path_response
from bloodhound_client.scoring import score_path_chain
from kerberoast_detector.spn_enum import parse_ldap_entry
from log_correlation.parser import parse_event_xml
from log_correlation.correlator import correlate_all
from hardening_engine.rules import build_recommendations
from narrator.prompts import build_brief_prompt

from tests.fixtures.sample_ldap_entries import ENTRY_RC4_ONLY
from tests.fixtures.sample_events import EVENT_4769_RC4, EVENT_4662_DCSYNC


def section(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def main():
    # --- Step 1: BloodHound attack path data ---------------------------
    section("STEP 1: BloodHound attack path (fixture data)")
    fixture_path = os.path.join("tests", "fixtures", "sample_path_response.json")
    with open(fixture_path) as f:
        raw_bh_data = json.load(f)
    paths = parse_path_response(raw_bh_data)

    for edge in paths:
        print(f"  {edge}")

    score = score_path_chain(paths)
    print(f"\n  Severity score: {score['severity_score']} "
          f"(edge score {score['total_edge_score']}, {score['hop_count']} hops)")
    print(f"  Edge chain: {' -> '.join(score['edge_kinds'])}")

    # --- Step 2: Kerberoasting detector (fixture LDAP data) -------------
    section("STEP 2: Kerberoasting detector (fixture LDAP data)")
    kerberoastable_accounts = [parse_ldap_entry(ENTRY_RC4_ONLY)]
    for acct in kerberoastable_accounts:
        print(f"  Account: {acct.sam_account_name}")
        print(f"  SPNs: {acct.spns}")
        print(f"  Encryption risk: {acct.encryption.risk_reason}")
        print(f"  High risk: {acct.is_high_risk}")

    # --- Step 3: Event log parser (fixture .evtx-derived XML) -----------
    section("STEP 3: Event log parser (fixture event data)")
    raw_events = [
        parse_event_xml(EVENT_4769_RC4),
        parse_event_xml(EVENT_4662_DCSYNC),
    ]
    for event in raw_events:
        print(f"  Event {event['event_id']} at {event['time_created']}")

    # --- Step 4: Correlation engine --------------------------------------
    section("STEP 4: Correlation engine")
    correlation_results = correlate_all(paths, kerberoastable_accounts, raw_events)

    for result in correlation_results:
        print(f"\n  Account: {result.account}")
        print(f"  Evidence type: {result.evidence_type}")
        print(f"  Severity boost: {result.severity_boost}")
        print(f"  Matched edges: {[e.raw.get('kind') for e in result.matched_edges]}")

    # --- Step 5: Hardening recommendations + AI narrator -----------------
    section("STEP 5: Hardening recommendations + AI narrator")

    top_finding = correlation_results[0]  # highest severity_boost (DCSync)
    edge_kinds = [e.raw.get("kind") for e in top_finding.matched_edges]

    recs = build_recommendations(edge_kinds=edge_kinds, evidence_type=top_finding.evidence_type)
    print(f"\n  Hardening recommendations for top finding ({top_finding.account}):")
    for rec in recs:
        print(f"    - {rec[:100]}...")

    prompt = build_brief_prompt(
        account=top_finding.account,
        evidence_type=top_finding.evidence_type,
        edge_kinds=edge_kinds,
        evidence=top_finding.evidence,
        hardening_recs=recs,
    )

    try:
        from config import load_config, ConfigError
        cfg = load_config()
        api_key = cfg.get("claude", {}).get("api_key")

        if not api_key or api_key == "REPLACE_ME":
            raise ValueError("No real Claude API key configured")

        from narrator.claude_client import ClaudeNarrator
        model = cfg.get("claude", {}).get("model", "claude-sonnet-5")
        narrator = ClaudeNarrator(api_key=api_key, model=model)
        brief = narrator.generate_brief(top_finding)

        print("\n  --- AI-Generated Executive Brief ---")
        print(brief)

    except Exception as e:
        print(f"\n  [!] Skipping live Claude API call ({e})")
        print("  Showing the prompt that WOULD have been sent instead:\n")
        print("  " + "\n  ".join(prompt.splitlines()))

    section("PIPELINE COMPLETE")
    print(f"  {len(paths)} path edges analyzed")
    print(f"  {len(kerberoastable_accounts)} Kerberoastable account(s) found")
    print(f"  {len(raw_events)} log events processed")
    print(f"  {len(correlation_results)} correlated finding(s) produced")


if __name__ == "__main__":
    main()
