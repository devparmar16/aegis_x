"""
Factory for constructing the active AIProvider based on AppConfig.

This is the only place in the codebase that decides *which* provider
class gets instantiated. Everything else programs against the abstract
`AIProvider` interface, so adding a new provider means: implement the
class, register it here, done.
"""

from __future__ import annotations

from app.ai.base_provider import AIProvider
from app.ai.gemini_provider import GeminiProvider
from app.ai.groq_provider import GroqProvider
from app.ai.null_provider import NullAIProvider
from app.ai.ollama_provider import OllamaProvider
from app.ai.openai_provider import OpenAIProvider
from app.config.config import AppConfig
from app.utils.logger import get_logger

logger = get_logger(__name__)


def create_ai_provider(config: AppConfig) -> AIProvider:
    """Build the AIProvider selected by `AI_PROVIDER` in .env.

    Falls back to NullAIProvider (rather than raising) if the provider
    is disabled or missing required credentials, so a misconfigured AI
    layer never prevents the rest of the pipeline (collection, risk
    scoring, UI, database) from working.
    """
    provider = config.ai_provider

    if provider == "groq":
        if not config.groq_api_key:
            logger.warning("AI_PROVIDER=groq but GROQ_API_KEY is not set; disabling AI")
            return NullAIProvider()
        return GroqProvider(
            api_key=config.groq_api_key,
            model_name=config.model_name,
            timeout_seconds=config.ai_request_timeout_seconds,
        )

    if provider == "gemini":
        if not config.gemini_api_key:
            logger.warning("AI_PROVIDER=gemini but GEMINI_API_KEY is not set; disabling AI")
            return NullAIProvider()
        return GeminiProvider(
            api_key=config.gemini_api_key,
            model_name=config.model_name,
            timeout_seconds=config.ai_request_timeout_seconds,
        )

    if provider == "openai":
        if not config.openai_api_key:
            logger.warning("AI_PROVIDER=openai but OPENAI_API_KEY is not set; disabling AI")
            return NullAIProvider()
        return OpenAIProvider(
            api_key=config.openai_api_key,
            model_name=config.model_name,
            timeout_seconds=config.ai_request_timeout_seconds,
        )

    if provider == "ollama":
        return OllamaProvider(
            base_url=config.ollama_base_url,
            model_name=config.model_name,
            timeout_seconds=config.ai_request_timeout_seconds,
        )

    if provider != "none":
        logger.warning("Unknown AI_PROVIDER '%s'; disabling AI", provider)

    return NullAIProvider()
