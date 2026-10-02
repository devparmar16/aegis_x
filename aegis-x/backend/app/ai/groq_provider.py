"""Groq AI provider (OpenAI-compatible chat completions API)."""

from __future__ import annotations

import requests

from app.ai.base_provider import AIProvider, build_prompt
from app.models.file_report import AIExplanation, FileReport
from app.utils.logger import get_logger

logger = get_logger(__name__)

_GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


class GroqProvider(AIProvider):
    """AI provider backed by Groq's hosted inference API."""

    provider_name = "groq"

    def __init__(self, api_key: str, model_name: str, timeout_seconds: int) -> None:
        self._api_key = api_key
        self._model_name = model_name
        self._timeout = timeout_seconds

    def analyze(self, file_report: FileReport) -> AIExplanation:
        prompt = build_prompt(file_report)
        try:
            response = requests.post(
                _GROQ_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model_name,
                    "messages": [
                        {"role": "system", "content": self._system_instructions()},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            raw_text = data["choices"][0]["message"]["content"]
            return self._parse_json_response(raw_text, self._model_name)
        except requests.RequestException as exc:
            logger.error("Groq API request failed: %s", exc)
            return self._error_explanation(self._model_name, str(exc))
        except (KeyError, IndexError) as exc:
            logger.error("Unexpected Groq response shape: %s", exc)
            return self._error_explanation(self._model_name, f"Unexpected response shape: {exc}")
