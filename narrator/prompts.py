"""
Prompt construction for the AI attack path narrator.

Kept separate from claude_client.py so prompt logic can be unit tested
without making any API calls -- prompts are just deterministic string
building based on correlation results and hardening recommendations.
"""


def build_brief_prompt(
    account: str,
    evidence_type: str,
    edge_kinds: list[str],
    evidence: dict,
    hardening_recs: list[str],
) -> str:
    """
    Builds a structured prompt asking Claude to produce a plain-English
    executive brief for one correlated attack path finding.

    Deliberately asks for consistent sections (Summary, Risk, Evidence
    of Exploitation, Recommended Action) so output is predictable
    enough to drop into a report template without extra parsing.
    """
    edge_summary = " -> ".join(edge_kinds) if edge_kinds else "unknown path"
    evidence_summary = "\n".join(f"- {k}: {v}" for k, v in evidence.items())
    recs_summary = "\n".join(f"- {r}" for r in hardening_recs) if hardening_recs else "None available."

    severity_label = {
        "active_dcsync_on_path": "CRITICAL -- confirmed active exploitation",
        "active_kerberoast_on_path": "HIGH -- confirmed active exploitation attempt",
        "kerberoastable_on_path": "MEDIUM -- theoretical exposure, no confirmed exploitation",
    }.get(evidence_type, "UNKNOWN")

    prompt = f"""You are a security analyst writing a brief for a non-technical executive audience (CISO, IT director) about an Active Directory attack path finding. Be direct, avoid unnecessary jargon, and keep it concise.

FINDING DETAILS:
- Account: {account}
- Evidence type: {evidence_type}
- Severity: {severity_label}
- Attack path edges: {edge_summary}
- Supporting evidence:
{evidence_summary}

AVAILABLE HARDENING RECOMMENDATIONS:
{recs_summary}

Write a brief with exactly these four sections, each 2-4 sentences:

## Summary
Plain-English explanation of what this finding means, avoiding Kerberos/AD jargon where possible.

## Business Risk
What could actually happen to the organization if this isn't addressed -- frame in terms of business impact, not technical mechanism.

## Evidence of Exploitation
State clearly whether this is a theoretical risk or confirmed active exploitation, based on the evidence provided. Do not overstate certainty beyond what the evidence supports.

## Recommended Action
The single most important next step, prioritized from the hardening recommendations provided. Be specific and actionable.
"""
    return prompt
