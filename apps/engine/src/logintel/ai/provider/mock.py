"""Deterministic Mock AI inference provider for LogIntel M5.2 testing.

Provides deterministic responses and fault injection without requiring
an external runtime daemon, network requests, or model weights.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from logintel.ai.domain.provider import (
    LocalAIProvider,
    ProviderCapabilities,
    ProviderHealth,
    ProviderResult,
)
from logintel.ai.errors import (
    ModelUnavailable,
    ProviderResponseTooLarge,
    ProviderTimeout,
    ProviderUnavailable,
)


class MockAIProvider(LocalAIProvider):
    """Deterministic Mock provider supporting fault injection for comprehensive security and isolation testing."""

    def __init__(
        self,
        provider_id: str = "mock",
        model_id: str = "mock-model-v1",
        default_response: Optional[str] = None,
        installed_models: Optional[List[str]] = None,
    ) -> None:
        capabilities = ProviderCapabilities(
            supports_streaming=False,
            supports_json_schema=True,
            context_window_tokens=4096,
            max_output_tokens=2048,
            requires_local_network=False,
        )
        super().__init__(provider_id=provider_id, model_id=model_id, capabilities=capabilities)

        self.default_response = default_response
        self.installed_models = installed_models if installed_models is not None else [model_id]
        
        # Fault injection controls
        self.simulate_unavailable: bool = False
        self.simulate_timeout: bool = False
        self.simulate_model_missing: bool = False
        self.simulate_oversized: bool = False
        self.simulate_crash: bool = False
        self.latency_ms: float = 2.5
        self.max_response_bytes: int = 1048576

        # Audit/recorded calls
        self.recorded_calls: List[Dict[str, Any]] = []

    async def is_available(self) -> bool:
        if self.simulate_unavailable or self.simulate_crash:
            return False
        return True

    async def health_check(self) -> ProviderHealth:
        if self.simulate_unavailable or self.simulate_crash:
            return ProviderHealth(
                is_healthy=False,
                provider_id=self.provider_id,
                active_model=self.model_id,
                active_model_available=False,
                error="Simulated provider unavailable",
            )
        is_avail = self.model_id in self.installed_models and not self.simulate_model_missing
        return ProviderHealth(
            is_healthy=True,
            provider_id=self.provider_id,
            runtime_version="mock-1.0.0",
            installed_models=list(self.installed_models),
            active_model=self.model_id,
            active_model_available=is_avail,
            latency_ms=self.latency_ms,
        )

    async def list_models(self) -> List[str]:
        if self.simulate_unavailable:
            return []
        return list(self.installed_models)

    async def is_model_available(self, model_name: Optional[str] = None) -> bool:
        if self.simulate_unavailable or self.simulate_model_missing:
            return False
        target = model_name or self.model_id
        return target in self.installed_models

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> ProviderResult:
        req_id = request_id or str(uuid.uuid4())
        self.recorded_calls.append({
            "request_id": req_id,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "schema": schema,
        })

        if self.simulate_unavailable or self.simulate_crash:
            raise ProviderUnavailable("Simulated provider connection failure")

        if self.simulate_timeout:
            raise ProviderTimeout("Simulated inference timeout deadline exceeded")

        if self.simulate_model_missing or not await self.is_model_available(self.model_id):
            raise ModelUnavailable(f"Model '{self.model_id}' is not installed in mock runtime")

        if self.simulate_oversized:
            oversized_data = "x" * (self.max_response_bytes + 1024)
            raise ProviderResponseTooLarge("Simulated oversized response payload")

        raw_output = self.default_response
        if raw_output is None:
            # Default minimal valid response structure
            raw_output = json.dumps({
                "answer_markdown": "Mock analytical investigation assessment.",
                "epistemic_status": "OBSERVED",
                "claims": [],
                "citations": [],
                "suggested_queries": [],
                "identified_unknowns": [],
            })

        return ProviderResult(
            request_id=req_id,
            raw_output=raw_output,
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_digest="sha256:mock_digest_12345",
            runtime_version="mock-1.0.0",
            prompt_tokens=42,
            completion_tokens=18,
            latency_ms=self.latency_ms,
            termination_reason="stop",
        )
