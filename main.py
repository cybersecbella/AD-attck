"""
AD Attack Path & Detection Platform -- main CLI entrypoint.

Two modes:
  --mode demo   Runs the full pipeline against fixture data (no Docker,
                no lab, no live credentials needed). Good for a first
                run, CI, or a quick demo. Default mode.
  --mode live   Runs against your real BloodHound CE instance and
                (optionally) a real .evtx file / LDAP domain, per
                config.yaml. Requires Docker + BloodHound running.

Usage:
    python main.py --smoke-test              # connectivity check only
    python main.py --mode demo                # full pipeline, fixture data
    python main.py --mode live --evtx-file path/to/security.evtx
"""

import argparse
import json
import sys

from config import load_config, ConfigError
from bloodhound_client.api import BloodHoundClient, BloodHoundAPIError
from bloodhound_client.queries import COUNT_ALL_USERS, SHORTEST_PATH_TO_DA
from bloodhound_client.models import parse_path_response
from bloodhound_client.scoring import score_path_chain
from kerberoast_detector.spn_enum import parse_ldap_entry, enumerate_spn_accounts
from log_correlation.parser import parse_event_xml
from log_correlation.evtx_reader import read_evtx_file
from log_correlation.correlator import correlate_all
from hardening_engine.rules import build_recommendations
from reports.report_builder import build_json_report, build_markdown_report, save_report

from tests.fixtures.sample_ldap_entries import ENTRY_RC4_ONLY
from tests.fixtures.sample_events import EVENT_4769_RC4, EVENT_4662_DCSYNC


def run_smoke_test(cfg: dict) -> None:
    bh_cfg = cfg["bloodhound"]
    if "api_id" not in bh_cfg:
        print("[!] This build only supports BloodHound CE (api_id/api_key). "
              "Legacy Neo4j support isn't implemented yet.")
        sys.exit(1)

    client = BloodHoundClient(
        base_url=bh_cfg["base_url"], api_id=bh_cfg["api_id"], api_key=bh_cfg["api_key"]
    )

    print(f"[*] Connecting to BloodHound CE at {bh_cfg['base_url']} ...")
    try:
        client.test_connection()
        print("[+] Server reachable, credentials valid.")
    except BloodHoundAPIError as e:
        print(f"[!] {e}")
        sys.exit(1)

    try:
        print("[*] Running sanity query: COUNT_ALL_USERS ...")
        result = client.run_cypher(COUNT_ALL_USERS)
        print(f"[+] Query OK. Result: {result}")
    except BloodHoundAPIError as e:
        print(f"[!] Query failed: {e}")
        sys.exit(1)

    print("[+] Smoke test passed.")


def get_demo_data():
    """Fixture-based data for --mode demo. Same scenario used throughout the test suite."""
    import os
    fixture_path = os.path.join(
        os.path.dirname(__file__), "tests", "fixtures", "sample_path_response.json"
    )
    with open(fixture_path) as f:
        paths = parse_path_response(json.load(f))

    kerberoastable_accounts = [parse_ldap_entry(ENTRY_RC4_ONLY)]
    raw_events = [parse_event_xml(EVENT_4769_RC4), parse_event_xml(EVENT_4662_DCSYNC)]

    return paths, kerberoastable_accounts, raw_events


def get_live_data(cfg: dict, evtx_file):
    """Live data for --mode live. Requires BloodHound running and (optionally) a real .evtx file."""
    bh_cfg = cfg["bloodhound"]
    domain_cfg = cfg["domain"]

    client = BloodHoundClient(
        base_url=bh_cfg["base_url"], api_id=bh_cfg["api_id"], api_key=bh_cfg["api_key"]
    )
    print("[*] Querying BloodHound for shortest paths to Domain Admins ...")
    raw_result = client.run_cypher(SHORTEST_PATH_TO_DA)
    paths = parse_path_response(raw_result)
    print(f"[+] Found {len(paths)} path edges.")

    print("[*] Enumerating Kerberoastable accounts via LDAP ...")
    kerberoastable_accounts = enumerate_spn_accounts(
        server=domain_cfg["ldap_server"],
        domain=domain_cfg.get("domain_fqdn", ""),
        username=domain_cfg["username"],
        password=domain_cfg["password"],
    )
    print(f"[+] Found {len(kerberoastable_accounts)} SPN account(s).")

    raw_events = []
    if evtx_file:
        print(f"[*] Reading event log: {evtx_file} ...")
        raw_events = list(read_evtx_file(evtx_file))
        print(f"[+] Parsed {len(raw_events)} relevant event(s).")
    else:
        print("[*] No --evtx-file provided -- skipping log correlation (path/Kerberoast findings only).")

    return paths, kerberoastable_accounts, raw_events


def run_pipeline(cfg: dict, mode: str, evtx_file, use_ai: bool) -> None:
    if mode == "demo":
        paths, kerberoastable_accounts, raw_events = get_demo_data()
        domain_label = "phantom.corp (demo fixture data)"
    else:
        paths, kerberoastable_accounts, raw_events = get_live_data(cfg, evtx_file)
        domain_label = cfg.get("domain", {}).get("ldap_server", "unknown")

    print("[*] Scoring path severity ...")
    score = score_path_chain(paths)
    print(f"[+] Severity score: {score['severity_score']} ({score['hop_count']} hops)")

    print("[*] Correlating findings ...")
    correlation_results = correlate_all(paths, kerberoastable_accounts, raw_events)
    print(f"[+] {len(correlation_results)} correlated finding(s).")

    narrator = None
    if use_ai:
        api_key = cfg.get("claude", {}).get("api_key")
        if api_key and api_key != "REPLACE_ME":
            from narrator.claude_client import ClaudeNarrator
            model = cfg.get("claude", {}).get("model", "claude-sonnet-5")
            narrator = ClaudeNarrator(api_key=api_key, model=model)
        else:
            print("[!] --ai requested but no valid Claude API key in config.yaml -- skipping AI briefs.")

    findings = []
    for result in correlation_results:
        edge_kinds = [e.raw.get("kind") for e in result.matched_edges]
        recs = build_recommendations(edge_kinds=edge_kinds, evidence_type=result.evidence_type)

        brief = None
        if narrator:
            print(f"[*] Generating AI brief for {result.account} ({result.evidence_type}) ...")
            brief = narrator.generate_brief(result)

        findings.append((result, recs, brief))

    print("[*] Building report ...")
    json_report = build_json_report(findings, domain=domain_label)
    md_report = build_markdown_report(json_report)
    json_path, md_path = save_report(json_report, md_report)

    print(f"\n[+] Reports written:")
    print(f"    {json_path}")
    print(f"    {md_path}")


def main():
    parser = argparse.ArgumentParser(description="AD Attack Path & Detection Platform")
    parser.add_argument("--smoke-test", action="store_true", help="Connectivity check only, then exit.")
    parser.add_argument(
        "--mode", choices=["demo", "live"], default="demo",
        help="demo = fixture data, no infra needed. live = real BloodHound + optional .evtx file. Default: demo.",
    )
    parser.add_argument("--evtx-file", default=None, help="Path to a real .evtx file (live mode only).")
    parser.add_argument("--ai", action="store_true", help="Generate AI executive briefs via Claude (requires API key in config.yaml).")
    args = parser.parse_args()

    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"[!] Config error: {e}")
        sys.exit(1)

    if args.smoke_test:
        run_smoke_test(cfg)
        return

    if args.mode == "live" and ("api_id" not in cfg.get("bloodhound", {})):
        print("[!] --mode live requires BloodHound CE credentials in config.yaml.")
        sys.exit(1)

    run_pipeline(cfg, mode=args.mode, evtx_file=args.evtx_file, use_ai=args.ai)


if __name__ == "__main__":
    main()
