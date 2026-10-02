"""Abstract local AI inference provider contracts for LogIntel.

Decouples the investigation domain from future inference runtimes (e.g. Ollama, llama.cpp)
without importing deep learning or vendor-specific packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class ProviderCapabilities(BaseModel):
    """Declared capabilities of a local inference provider."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    supports_streaming: bool = False
    supports_json_schema: bool = True
    context_window_tokens: int = 4096
    max_output_tokens: int = 2048
    requires_local_network: bool = True


class ProviderHealth(BaseModel):
    """Diagnostic health and status information for a local inference provider."""

    model_config = ConfigDict(extra="forbid")

    is_healthy: bool
    provider_id: str
    runtime_version: Optional[str] = None
    installed_models: List[str] = Field(default_factory=list)
    active_model: str
    active_model_available: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProviderResult(BaseModel):
    """Untrusted raw output received from a local AI provider."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_output: str
    provider_id: str
    model_id: str
    model_digest: Optional[str] = None
    runtime_version: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[float] = None
    termination_reason: Optional[str] = "stop"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LocalAIProvider(ABC):
    """Abstract interface that local inference runtimes must implement."""

    def __init__(self, provider_id: str, model_id: str, capabilities: ProviderCapabilities) -> None:
        self.provider_id = provider_id
        self.model_id = model_id
        self.capabilities = capabilities

    @abstractmethod
    async def is_available(self) -> bool:
        """Check whether the local runtime daemon/binary is reachable."""
        pass

    async def health_check(self) -> ProviderHealth:
        """Execute health check against the local runtime."""
        avail = await self.is_available()
        return ProviderHealth(
            is_healthy=avail,
            provider_id=self.provider_id,
            active_model=self.model_id,
            active_model_available=avail,
        )

    async def list_models(self) -> List[str]:
        """List all models currently installed and available in the local runtime."""
        return [self.model_id] if await self.is_available() else []

    async def is_model_available(self, model_name: Optional[str] = None) -> bool:
        """Check if the active model or specified model is installed locally."""
        target = model_name or self.model_id
        return target == self.model_id and await self.is_available()

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> ProviderResult:
        """Execute local model inference and return an untrusted ProviderResult."""
        pass
