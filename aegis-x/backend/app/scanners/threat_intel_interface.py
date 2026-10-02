"""Threat intelligence provider interface and stub implementations."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

from app.config.config import AppConfig
from app.models.file_report import ThreatIntelResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelProvider(ABC):
    """Interface for external threat intelligence services."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g. 'VirusTotal')."""
        pass

    @abstractmethod
    def hash_lookup(self, sha256: str) -> ThreatIntelResult:
        """Look up a file hash on the provider."""
        pass


class NullThreatIntelProvider(ThreatIntelProvider):
    """No-op provider when threat intel is disabled or unconfigured."""

    @property
    def provider_name(self) -> str:
        return "none"

    def hash_lookup(self, sha256: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider="none",
            sha256=sha256,
            status="unavailable",
            error="Threat intelligence is disabled or unconfigured.",
        )


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 API implementation (Stub)."""

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    def hash_lookup(self, sha256: str) -> ThreatIntelResult:
        # Full integration to be completed in a later phase.
        # This returns UNAVAILABLE cleanly for now.
        if not self.config.virustotal_api_key:
            return ThreatIntelResult(
                provider=self.provider_name,
                sha256=sha256,
                status="unavailable",
                error="Missing VirusTotal API key.",
            )

        import requests

        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.config.virustotal_api_key}
            response = requests.get(url, headers=headers, timeout=self.config.scanner_timeout_seconds)
            
            if response.status_code == 404:
                return ThreatIntelResult(
                    provider=self.provider_name,
                    sha256=sha256,
                    status="not_found",
                    found=False
                )
                
            response.raise_for_status()
            data = response.json()
            
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            
            return ThreatIntelResult(
                provider=self.provider_name,
                sha256=sha256,
                status="malicious" if malicious else "clean",
                found=True,
                malicious=malicious,
                raw_response=data
            )
            
        except Exception as exc:
            logger.error("VirusTotal lookup failed for %s: %s", sha256, exc)
            return ThreatIntelResult(
                provider=self.provider_name,
                sha256=sha256,
                status="error",
                error=str(exc)
            )


def create_threat_intel_provider(config: AppConfig) -> ThreatIntelProvider:
    """Factory to create the appropriate threat intel provider."""
    if not config.threat_intel_enabled:
        return NullThreatIntelProvider(config)
    
    if config.virustotal_api_key:
        return VirusTotalProvider(config)
        
    return NullThreatIntelProvider(config)
