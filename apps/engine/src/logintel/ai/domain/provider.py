"""Abstract local AI inference provider contracts for LogIntel.

Decouples the investigation domain from future inference runtimes (e.g. Ollama, llama.cpp)
without importing deep learning or vendor-specific packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ProviderCapabilities(BaseModel):
    """Declared capabilities of a local inference provider."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    supports_streaming: bool = False
    supports_json_schema: bool = True
    context_window_tokens: int = 4096
    max_output_tokens: int = 2048


class ProviderResult(BaseModel):
    """Untrusted raw output received from a local AI provider."""

    model_config = ConfigDict(extra="forbid")

    raw_output: str
    provider_id: str
    model_id: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LocalAIProvider(ABC):
    """Abstract interface that future local inference runtimes must implement."""

    def __init__(self, provider_id: str, model_id: str, capabilities: ProviderCapabilities) -> None:
        self.provider_id = provider_id
        self.model_id = model_id
        self.capabilities = capabilities

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        """Execute local model inference and return an untrusted ProviderResult."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check whether the local runtime daemon/binary is reachable and healthy."""
        pass
