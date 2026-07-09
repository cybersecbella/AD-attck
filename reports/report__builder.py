"""
Builds JSON and Markdown reports from a completed pipeline run
(correlation results + hardening recommendations + optional AI briefs).

Kept separate from main.py's orchestration so report formatting can be
unit tested against static input dicts, without needing a live pipeline
run.
"""

import json
import os
from datetime import datetime, timezone

from log_correlation.correlator import CorrelationResult


def _serialize_finding(
    result: CorrelationResult,
    hardening_recs: list[str],
    ai_brief: str | None = None,
) -> dict:
    return {
        "account": result.account,
        "evidence_type": result.evidence_type,
        "severity_boost": result.severity_boost,
        "matched_edges": [
            {"start": e.start_node, "end": e.end_node, "kind": e.raw.get("kind")}
            for e in result.matched_edges
        ],
        "evidence": result.evidence,
        "hardening_recommendations": hardening_recs,
        "ai_brief": ai_brief,
    }


def build_json_report(
    findings: list[tuple[CorrelationResult, list[str], str | None]],
    domain: str = "unknown",
) -> dict:
    """
    findings: list of (CorrelationResult, hardening_recs, ai_brief_or_none) tuples,
    already sorted in the order you want them to appear in the report
    (correlate_all() already sorts by severity_boost descending).
    """
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "finding_count": len(findings),
        "findings": [
            _serialize_finding(result, recs, brief) for result, recs, brief in findings
        ],
    }


def build_markdown_report(json_report: dict) -> str:
    lines = [
        f"# AD Attack Path & Detection Report",
        f"",
        f"**Domain:** {json_report['domain']}  ",
        f"**Generated:** {json_report['generated_at']}  ",
        f"**Findings:** {json_report['finding_count']}",
        f"",
        f"---",
        f"",
    ]

    severity_labels = {
        "active_dcsync_on_path": "🔴 CRITICAL",
        "active_kerberoast_on_path": "🟠 HIGH",
        "kerberoastable_on_path": "🟡 MEDIUM",
    }

    for i, finding in enumerate(json_report["findings"], start=1):
        label = severity_labels.get(finding["evidence_type"], "⚪ UNKNOWN")
        edge_chain = " → ".join(
            e["kind"] or "?" for e in finding["matched_edges"]
        ) or "N/A"

        lines.append(f"## {i}. {finding['account']} -- {label}")
        lines.append(f"")
        lines.append(f"- **Evidence type:** `{finding['evidence_type']}`")
        lines.append(f"- **Severity score:** {finding['severity_boost']}")
        lines.append(f"- **Attack path:** {edge_chain}")
        lines.append(f"")

        if finding["ai_brief"]:
            lines.append(finding["ai_brief"])
            lines.append(f"")
        else:
            lines.append(f"**Evidence:**")
            for k, v in finding["evidence"].items():
                lines.append(f"- {k}: {v}")
            lines.append(f"")
            lines.append(f"**Recommendations:**")
            for rec in finding["hardening_recommendations"]:
                lines.append(f"- {rec}")
            lines.append(f"")

        lines.append(f"---")
        lines.append(f"")

    return "\n".join(lines)


def save_report(json_report: dict, md_report: str, output_dir: str = "reports") -> tuple[str, str]:
    """
    Writes both report formats to disk with a shared timestamp-based
    filename, and returns the (json_path, md_path) written.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"report_{timestamp}.json")
    md_path = os.path.join(output_dir, f"report_{timestamp}.md")

    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2)

    with open(md_path, "w") as f:
        f.write(md_report)

    return json_path, md_path
