"""Google Gemini AI provider."""

from __future__ import annotations

import requests

from app.ai.base_provider import AIProvider, build_prompt
from app.models.file_report import AIExplanation, FileReport
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GeminiProvider(AIProvider):
    """AI provider backed by Google's Gemini generative language API."""

    provider_name = "gemini"

    def __init__(self, api_key: str, model_name: str, timeout_seconds: int) -> None:
        self._api_key = api_key
        self._model_name = model_name
        self._timeout = timeout_seconds

    def _endpoint(self) -> str:
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model_name}:generateContent?key={self._api_key}"
        )

    def analyze(self, file_report: FileReport) -> AIExplanation:
        prompt = build_prompt(file_report)
        combined_prompt = f"{self._system_instructions()}\n\nEVIDENCE:\n{prompt}"

        try:
            response = requests.post(
                self._endpoint(),
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": combined_prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "responseMimeType": "application/json",
                    },
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            return self._parse_json_response(raw_text, self._model_name)
        except requests.RequestException as exc:
            logger.error("Gemini API request failed: %s", exc)
            return self._error_explanation(self._model_name, str(exc))
        except (KeyError, IndexError) as exc:
            logger.error("Unexpected Gemini response shape: %s", exc)
            return self._error_explanation(self._model_name, f"Unexpected response shape: {exc}")
