"""
Abstract AI provider interface.

CRITICAL DESIGN CONSTRAINT: the AI layer never decides severity. It is
given the risk engine's already-computed evidence and score, and its
only job is to explain that evidence in plain language. Every concrete
provider implements the same `analyze()` contract so the rest of the
app (and the UI) never needs to know which backend produced the
explanation.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict

from app.models.file_report import AIExplanation, FileReport
from app.utils.logger import get_logger

logger = get_logger(__name__)


_SYSTEM_INSTRUCTIONS = (
    "You are a security analyst assistant embedded in an endpoint "
    "exposure management tool called Aegis-X. You are given structured "
    "evidence about a downloaded file, INCLUDING an already-computed "
    "deterministic risk score and severity that a separate scoring "
    "engine produced. You do NOT decide or restate a different "
    "severity or score. Your only job is to explain, in plain "
    "language and using ONLY the evidence provided, the following six "
    "points as a JSON object with these exact keys: "
    "what_it_appears_to_be, why_evidence_matters, "
    "possible_attack_techniques, potential_impact, "
    "recommended_precautions, confidence_level. "
    "Do not invent evidence that was not supplied. If evidence is "
    "insufficient for a point, say so plainly. Respond with ONLY the "
    "JSON object, no markdown fences, no preamble."
)


def build_prompt(report: FileReport) -> str:
    """Build the structured JSON prompt sent to the AI provider.

    The AI receives evidence AND the risk engine's verdict, but is
    explicitly instructed (see _SYSTEM_INSTRUCTIONS) not to override it.
    """
    payload: Dict[str, Any] = {
        "evidence": report.to_evidence_dict(),
        "deterministic_risk_assessment": {
            "score": report.risk.score if report.risk else None,
            "severity": report.risk.severity.value if report.risk else None,
            "triggered_factors": [
                {"name": f.name, "description": f.description}
                for f in (report.risk.factors if report.risk else [])
                if f.triggered
            ],
        },
    }
    return json.dumps(payload, indent=2, default=str)


class AIProvider(ABC):
    """Abstract base class every AI backend implements."""

    provider_name: str = "unknown"

    @abstractmethod
    def analyze(self, file_report: FileReport) -> AIExplanation:
        """Return an explanatory (non-authoritative) analysis of the report."""
        raise NotImplementedError

    def _system_instructions(self) -> str:
        return _SYSTEM_INSTRUCTIONS

    def _error_explanation(self, model_name: str, error: str) -> AIExplanation:
        """Shared fallback used by every provider when a call fails, so
        one provider's outage never crashes the analysis pipeline.
        """
        return AIExplanation(
            provider=self.provider_name,
            model=model_name,
            what_it_appears_to_be="",
            why_evidence_matters="",
            possible_attack_techniques="",
            potential_impact="",
            recommended_precautions="AI explanation unavailable; rely on the "
                                     "deterministic risk factors above.",
            confidence_level="unknown",
            error=error,
        )

    def _parse_json_response(self, raw_text: str, model_name: str) -> AIExplanation:
        """Parse a provider's raw text response into an AIExplanation,
        tolerating minor formatting issues (e.g. stray markdown fences).
        """
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
            return AIExplanation(
                provider=self.provider_name,
                model=model_name,
                what_it_appears_to_be=str(data.get("what_it_appears_to_be", "")),
                why_evidence_matters=str(data.get("why_evidence_matters", "")),
                possible_attack_techniques=str(data.get("possible_attack_techniques", "")),
                potential_impact=str(data.get("potential_impact", "")),
                recommended_precautions=str(data.get("recommended_precautions", "")),
                confidence_level=str(data.get("confidence_level", "unknown")),
                raw_response=raw_text,
            )
        except (json.JSONDecodeError, AttributeError) as exc:
            logger.warning(
                "Failed to parse AI response as JSON (%s); returning raw text", exc
            )
            return AIExplanation(
                provider=self.provider_name,
                model=model_name,
                what_it_appears_to_be="",
                why_evidence_matters="",
                possible_attack_techniques="",
                potential_impact="",
                recommended_precautions="",
                confidence_level="unknown",
                raw_response=raw_text,
                error="AI response was not valid JSON; see raw_response",
            )
