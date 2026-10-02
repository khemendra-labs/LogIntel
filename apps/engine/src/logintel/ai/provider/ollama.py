"""Ollama local AI inference provider implementation for LogIntel."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from logintel.ai.config import EndpointValidator, ProviderConfig, ModelConfig
from logintel.ai.domain.provider import (
    LocalAIProvider,
    ProviderCapabilities,
    ProviderHealth,
    ProviderResult,
)
from logintel.ai.errors import (
    ModelUnavailable,
    ProviderMalformedResponse,
    ProviderResponseTooLarge,
    ProviderTimeout,
    ProviderUnavailable,
)
from logintel.logging import get_logger

logger = get_logger("ai.provider.ollama")


class OllamaProvider(LocalAIProvider):
    """Local AI inference provider that interfaces directly with a locally running Ollama daemon."""

    def __init__(
        self,
        config: Optional[ProviderConfig] = None,
        model_config: Optional[ModelConfig] = None,
        max_response_bytes: int = 1048576,
    ) -> None:
        self.config = config or ProviderConfig()
        self.model_config = model_config or ModelConfig()
        self.max_response_bytes = max_response_bytes

        # Enforce strict local-only network boundary
        self.endpoint = EndpointValidator.validate_local_endpoint(self.config.endpoint)
        self.model_id = self.model_config.model_name

        capabilities = ProviderCapabilities(
            supports_streaming=False,
            supports_json_schema=True,
            context_window_tokens=self.model_config.context_window_tokens,
            max_output_tokens=self.model_config.max_tokens,
            requires_local_network=True,
        )

        super().__init__(
            provider_id="ollama",
            model_id=self.model_id,
            capabilities=capabilities,
        )

        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            timeout=httpx.Timeout(
                connect=self.config.connect_timeout_seconds,
                read=self.config.timeout_seconds,
                write=self.config.connect_timeout_seconds,
                pool=self.config.connect_timeout_seconds,
            ),
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        )

    async def close(self) -> None:
        """Close underlying HTTP client session."""
        await self._client.aclose()

    async def is_available(self) -> bool:
        """Check whether local Ollama daemon is reachable."""
        try:
            resp = await self._client.get("/api/version")
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return False

    async def health_check(self) -> ProviderHealth:
        """Execute full health check against local Ollama service and installed models."""
        t0 = time.perf_counter()
        try:
            v_resp = await self._client.get("/api/version")
            if v_resp.status_code != 200:
                return ProviderHealth(
                    is_healthy=False,
                    provider_id=self.provider_id,
                    active_model=self.model_id,
                    active_model_available=False,
                    error=f"Ollama returned HTTP status {v_resp.status_code}",
                )

            version_data = v_resp.json()
            runtime_version = version_data.get("version", "unknown")

            models = await self.list_models()
            is_active_avail = self._is_model_in_list(self.model_id, models)
            latency_ms = (time.perf_counter() - t0) * 1000

            return ProviderHealth(
                is_healthy=True,
                provider_id=self.provider_id,
                runtime_version=runtime_version,
                installed_models=models,
                active_model=self.model_id,
                active_model_available=is_active_avail,
                latency_ms=round(latency_ms, 2),
            )
        except httpx.ConnectError as e:
            return ProviderHealth(
                is_healthy=False,
                provider_id=self.provider_id,
                active_model=self.model_id,
                active_model_available=False,
                error=f"Connection refused to local Ollama daemon at {self.endpoint}",
            )
        except httpx.TimeoutException as e:
            return ProviderHealth(
                is_healthy=False,
                provider_id=self.provider_id,
                active_model=self.model_id,
                active_model_available=False,
                error="Health check timed out connecting to local Ollama daemon",
            )
        except Exception as e:
            return ProviderHealth(
                is_healthy=False,
                provider_id=self.provider_id,
                active_model=self.model_id,
                active_model_available=False,
                error=f"Unexpected health check failure: {str(e)}",
            )

    async def list_models(self) -> List[str]:
        """List all models currently installed and available in local Ollama daemon."""
        try:
            resp = await self._client.get("/api/tags")
            if resp.status_code != 200:
                return []
            data = resp.json()
            models_list = data.get("models", [])
            return [m.get("name") for m in models_list if "name" in m]
        except Exception as e:
            logger.warning("Failed to list installed Ollama models: %s", e)
            return []

    async def is_model_available(self, model_name: Optional[str] = None) -> bool:
        """Check whether the active or target model is installed locally."""
        target = model_name or self.model_id
        installed = await self.list_models()
        return self._is_model_in_list(target, installed)

    def _is_model_in_list(self, target: str, installed: List[str]) -> bool:
        """Helper to match model names considering tag defaults (e.g. 'qwen2.5:7b' vs 'qwen2.5:7b:latest')."""
        target_lower = target.lower()
        for m in installed:
            m_lower = m.lower()
            if m_lower == target_lower or m_lower.startswith(f"{target_lower}:") or target_lower.startswith(f"{m_lower}:"):
                return True
        return False

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> ProviderResult:
        """Execute local model completion via Ollama `/api/generate`."""
        req_id = request_id or str(uuid.uuid4())

        # Check model presence first to fail fast with typed error
        if not await self.is_model_available(self.model_id):
            raise ModelUnavailable(
                f"Model '{self.model_id}' is not installed in local Ollama runtime. Use 'ollama pull {self.model_id}' first.",
                details={"model_id": self.model_id, "provider": self.provider_id},
            )

        payload: Dict[str, Any] = {
            "model": self.model_id,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.model_config.temperature,
                "top_p": self.model_config.top_p,
                "num_predict": self.model_config.max_tokens,
                "num_ctx": self.model_config.context_window_tokens,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        if schema or self.capabilities.supports_json_schema:
            payload["format"] = "json"

        t0 = time.perf_counter()
        try:
            resp = await self._client.post("/api/generate", json=payload)
        except httpx.ConnectError as e:
            raise ProviderUnavailable(
                f"Cannot connect to local Ollama daemon at {self.endpoint}: {e}",
                details={"endpoint": self.endpoint, "error": str(e)},
            ) from e
        except httpx.TimeoutException as e:
            raise ProviderTimeout(
                f"Ollama generation timed out after {self.config.timeout_seconds}s",
                details={"timeout_seconds": self.config.timeout_seconds},
            ) from e
        except httpx.RequestError as e:
            raise ProviderUnavailable(
                f"Ollama request error: {e}",
                details={"endpoint": self.endpoint, "error": str(e)},
            ) from e

        latency_ms = (time.perf_counter() - t0) * 1000

        # Enforce response payload size limit
        raw_bytes = resp.content
        if len(raw_bytes) > self.max_response_bytes:
            raise ProviderResponseTooLarge(
                f"Ollama response size ({len(raw_bytes)} bytes) exceeded limit of {self.max_response_bytes} bytes",
                details={"size_bytes": len(raw_bytes), "max_bytes": self.max_response_bytes},
            )

        if resp.status_code == 404:
            raise ModelUnavailable(
                f"Ollama reported model '{self.model_id}' not found",
                details={"model_id": self.model_id, "status_code": resp.status_code},
            )

        if resp.status_code != 200:
            raise ProviderMalformedResponse(
                f"Ollama returned unexpected HTTP error status {resp.status_code}",
                details={"status_code": resp.status_code, "body": resp.text[:200]},
            )

        try:
            data = resp.json()
        except Exception as e:
            raise ProviderMalformedResponse(
                f"Ollama response body is not valid JSON: {e}",
                details={"body_snippet": resp.text[:200]},
            ) from e

        raw_output = data.get("response", "")
        prompt_tokens = data.get("prompt_eval_count")
        completion_tokens = data.get("eval_count")
        done_reason = data.get("done_reason", "stop")

        return ProviderResult(
            request_id=req_id,
            raw_output=raw_output,
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_digest=data.get("digest"),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=round(latency_ms, 2),
            termination_reason=done_reason,
            metadata={
                "total_duration_ns": data.get("total_duration"),
                "load_duration_ns": data.get("load_duration"),
            },
        )
