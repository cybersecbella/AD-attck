"""
Correlation engine: cross-references BloodHound attack path accounts
against live evidence -- Kerberoasting attempts (4769/RC4) and DCSync
activity (4662) from the event log parser, and weak-crypto exposure
from the Kerberoasting detector.

This is what turns "here's a risky path" into "here's a risky path
AND someone is actively walking it" -- the differentiator described
in the project plan's Section 6 (build walkthrough).

Account name matching note: BloodHound labels nodes as
"accountname@DOMAIN.TLD" (e.g. "helpdesk_svc@PHANTOM.CORP"), while
Windows Event Logs and LDAP typically use bare sAMAccountName
("helpdesk_svc"). normalize_account_name() strips the domain suffix
and lowercases so both sides can be compared reliably.
"""

from dataclasses import dataclass, field

from bloodhound_client.models import AttackPath
from log_correlation.parser import check_kerberoast_indicator, check_dcsync_indicator


def normalize_account_name(name: str) -> str:
    if not name:
        return ""
    return name.split("@")[0].strip().lower()


@dataclass
class CorrelationResult:
    account: str
    evidence_type: str  # "kerberoastable_on_path" | "active_kerberoast_on_path" | "active_dcsync_on_path"
    matched_edges: list[AttackPath] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    severity_boost: int = 0

    def __repr__(self):
        return f"<CorrelationResult {self.account} :: {self.evidence_type}>"


def _accounts_on_paths(paths: list[AttackPath]) -> dict[str, list[AttackPath]]:
    """Maps normalized account name -> list of edges that account appears in
    (as either the source or target node)."""
    mapping: dict[str, list[AttackPath]] = {}
    for edge in paths:
        for node_label in (edge.start_node, edge.end_node):
            key = normalize_account_name(node_label)
            if not key or key == "unknown":
                continue
            mapping.setdefault(key, []).append(edge)
    return mapping


def correlate_kerberoastable_accounts(
    paths: list[AttackPath], kerberoastable_accounts: list
) -> list[CorrelationResult]:
    """
    Cross-references accounts flagged as weak-crypto/Kerberoastable
    (from kerberoast_detector) against accounts that appear on a
    BloodHound attack path. This surfaces "roastable AND on a path to
    something valuable" -- the accounts worth remediating first.
    """
    path_accounts = _accounts_on_paths(paths)
    results = []

    for account in kerberoastable_accounts:
        key = normalize_account_name(account.sam_account_name)
        if key in path_accounts and account.is_high_risk:
            results.append(
                CorrelationResult(
                    account=account.sam_account_name,
                    evidence_type="kerberoastable_on_path",
                    matched_edges=path_accounts[key],
                    evidence={
                        "spns": account.spns,
                        "encryption_risk": account.encryption.risk_reason if account.encryption else None,
                    },
                    severity_boost=5,
                )
            )
    return results


def correlate_log_events(
    paths: list[AttackPath], raw_events: list[dict]
) -> list[CorrelationResult]:
    """
    Cross-references parsed log events (from log_correlation.parser)
    against accounts on BloodHound paths. This is the "active
    exploitation in progress" signal -- much higher urgency than a
    theoretical roastable account, since it means someone actually did it.

    raw_events should be already-parsed event dicts (parser.parse_event_xml
    output), not raw XML.
    """
    path_accounts = _accounts_on_paths(paths)
    results = []

    for event in raw_events:
        kerb_hit = check_kerberoast_indicator(event)
        if kerb_hit and kerb_hit["is_weak"]:
            key = normalize_account_name(kerb_hit["account"])
            if key in path_accounts:
                results.append(
                    CorrelationResult(
                        account=kerb_hit["account"],
                        evidence_type="active_kerberoast_on_path",
                        matched_edges=path_accounts[key],
                        evidence=kerb_hit,
                        severity_boost=15,  # active exploitation outweighs theoretical risk
                    )
                )
            continue

        dcsync_hit = check_dcsync_indicator(event)
        if dcsync_hit:
            key = normalize_account_name(dcsync_hit["subject_account"])
            if key in path_accounts:
                results.append(
                    CorrelationResult(
                        account=dcsync_hit["subject_account"],
                        evidence_type="active_dcsync_on_path",
                        matched_edges=path_accounts[key],
                        evidence=dcsync_hit,
                        severity_boost=25,  # DCSync in progress is about as bad as it gets
                    )
                )

    return results


def correlate_all(
    paths: list[AttackPath],
    kerberoastable_accounts: list,
    raw_events: list[dict],
) -> list[CorrelationResult]:
    """
    Runs all correlation passes and returns a combined, severity-sorted
    list. This is the function main orchestration (Phase 5) will call.
    """
    results = []
    results.extend(correlate_kerberoastable_accounts(paths, kerberoastable_accounts))
    results.extend(correlate_log_events(paths, raw_events))

    results.sort(key=lambda r: r.severity_boost, reverse=True)
    return results
