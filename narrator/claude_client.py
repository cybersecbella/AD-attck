"""
Claude API client for generating plain-English executive briefs from
correlation findings.

Requires: pip install anthropic
Requires a valid Anthropic API key in config.yaml (claude.api_key).

This module is not covered by automated tests -- it makes a real,
billed API call. narrator/prompts.py (the prompt construction logic
this module depends on) is fully unit tested instead.
"""

from log_correlation.correlator import CorrelationResult
from hardening_engine.rules import build_recommendations
from narrator.prompts import build_brief_prompt

DEFAULT_MODEL = "claude-sonnet-5"  # good cost/quality balance for this use case;
                                     # see config.yaml to override


class NarratorError(Exception):
    pass


class ClaudeNarrator:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL):
        try:
            import anthropic
        except ImportError as e:
            raise ImportError(
                "anthropic SDK is required for the narrator. Install it with: pip install anthropic"
            ) from e

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate_brief(self, correlation_result: CorrelationResult) -> str:
        """
        Generates a plain-English executive brief for one correlation
        finding, incorporating relevant hardening recommendations.
        """
        edge_kinds = [
            edge.raw.get("kind") for edge in correlation_result.matched_edges
        ]
        hardening_recs = build_recommendations(
            edge_kinds=edge_kinds,
            evidence_type=correlation_result.evidence_type,
        )

        prompt = build_brief_prompt(
            account=correlation_result.account,
            evidence_type=correlation_result.evidence_type,
            edge_kinds=edge_kinds,
            evidence=correlation_result.evidence,
            hardening_recs=hardening_recs,
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:
            raise NarratorError(f"Claude API call failed: {e}") from e

        # response.content is a list of content blocks; join any text blocks
        text_blocks = [block.text for block in response.content if hasattr(block, "text")]
        return "\n".join(text_blocks)

    def generate_briefs(self, correlation_results: list[CorrelationResult]) -> dict[str, str]:
        """Generates briefs for multiple findings, keyed by account name.
        Simple sequential loop -- fine for a "top 10" scale list; batch
        this differently if you ever need to scale past that."""
        briefs = {}
        for result in correlation_results:
            briefs[f"{result.account}::{result.evidence_type}"] = self.generate_brief(result)
        return briefs
