"""Ollama AI provider for locally-hosted models — no API key required."""

from __future__ import annotations

import requests

from app.ai.base_provider import AIProvider, build_prompt
from app.models.file_report import AIExplanation, FileReport
from app.utils.logger import get_logger

logger = get_logger(__name__)


class OllamaProvider(AIProvider):
    """AI provider backed by a local Ollama server."""

    provider_name = "ollama"

    def __init__(self, base_url: str, model_name: str, timeout_seconds: int) -> None:
        self._base_url = base_url.rstrip("/")
        self._model_name = model_name
        self._timeout = timeout_seconds

    def analyze(self, file_report: FileReport) -> AIExplanation:
        prompt = build_prompt(file_report)
        combined_prompt = f"{self._system_instructions()}\n\nEVIDENCE:\n{prompt}"

        try:
            response = requests.post(
                f"{self._base_url}/api/generate",
                json={
                    "model": self._model_name,
                    "prompt": combined_prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.2},
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            raw_text = data.get("response", "")
            return self._parse_json_response(raw_text, self._model_name)
        except requests.RequestException as exc:
            logger.error("Ollama request failed: %s", exc)
            return self._error_explanation(
                self._model_name,
                f"{exc} (is Ollama running at {self._base_url}?)",
            )
