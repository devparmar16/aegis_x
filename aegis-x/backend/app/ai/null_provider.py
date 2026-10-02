"""
Fallback provider used when AI_PROVIDER=none, or when the configured
provider is missing required credentials. Guarantees the analysis
pipeline always produces a report even with AI fully disabled.
"""

from __future__ import annotations

from app.ai.base_provider import AIProvider
from app.models.file_report import AIExplanation, FileReport


class NullAIProvider(AIProvider):
    """No-op AI provider — returns a clearly-labeled placeholder explanation."""

    provider_name = "none"

    def analyze(self, file_report: FileReport) -> AIExplanation:
        return AIExplanation(
            provider=self.provider_name,
            model="n/a",
            what_it_appears_to_be="AI analysis is disabled.",
            why_evidence_matters="Refer to the deterministic risk factors above.",
            possible_attack_techniques="Not available (AI disabled).",
            potential_impact="Not available (AI disabled).",
            recommended_precautions=(
                "Review the deterministic risk score and factors; enable an "
                "AI_PROVIDER in .env for a plain-language explanation."
            ),
            confidence_level="n/a",
        )
