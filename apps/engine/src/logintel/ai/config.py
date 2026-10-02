"""Configuration and Network Boundary Validation for LogIntel M5.2 Local AI Subsystem."""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from logintel.ai.errors import UnsafeProviderEndpoint

ALLOWED_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


class AIProviderType(str, Enum):
    """Supported local AI provider types."""

    OLLAMA = "ollama"
    MOCK = "mock"
    LLAMACPP = "llamacpp"


class EndpointValidator:
    """Enforces strict local-only network boundary rules for provider endpoints."""

    @staticmethod
    def validate_local_endpoint(endpoint_url: str, allow_remote: bool = False) -> str:
        """Validate that endpoint URL is local-only unless explicit remote bypass is enabled.
        
        Rejects remote IPs, public internet domains, 0.0.0.0, LAN addresses, and cloud APIs.
        """
        if not endpoint_url or not isinstance(endpoint_url, str):
            raise UnsafeProviderEndpoint("Provider endpoint URL cannot be empty")

        parsed = urlparse(endpoint_url.strip())
        if parsed.scheme not in ("http", "https"):
            raise UnsafeProviderEndpoint(
                f"Invalid URL scheme '{parsed.scheme}'; only http and https are permitted",
                details={"endpoint": endpoint_url, "scheme": parsed.scheme},
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise UnsafeProviderEndpoint(
                "Provider endpoint URL must specify a valid host",
                details={"endpoint": endpoint_url},
            )

        if allow_remote:
            return endpoint_url

        # Check explicit local whitelist
        if hostname in ALLOWED_LOCAL_HOSTNAMES:
            return endpoint_url

        # Check IP address loopback
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback:
                return endpoint_url
            else:
                raise UnsafeProviderEndpoint(
                    f"Non-loopback IP address '{hostname}' is forbidden under local-only network policy",
                    details={"endpoint": endpoint_url, "ip": hostname, "is_loopback": False},
                )
        except ValueError:
            # Hostname is not an IP literal and not in local whitelist
            raise UnsafeProviderEndpoint(
                f"External host '{hostname}' is rejected. AI provider must be strictly local (127.0.0.1 / localhost)",
                details={"endpoint": endpoint_url, "hostname": hostname},
            )


class ProviderConfig(BaseModel):
    """Configuration for an individual local inference provider."""

    model_config = ConfigDict(extra="forbid")

    provider_type: AIProviderType = Field(default=AIProviderType.OLLAMA)
    endpoint: str = Field(default="http://127.0.0.1:11434")
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=600.0)
    connect_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    max_retries: int = Field(default=1, ge=0, le=3)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint_is_local(cls, v: str) -> str:
        return EndpointValidator.validate_local_endpoint(v)


class ModelConfig(BaseModel):
    """Configuration for the local AI model."""

    model_config = ConfigDict(extra="forbid")

    model_name: str = Field(default="qwen2.5:0.5b", min_length=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=0.9, ge=0.0, le=1.0)
    max_tokens: int = Field(default=512, ge=128, le=8192)
    context_window_tokens: int = Field(default=2048, ge=512, le=32768)
    chars_per_token: float = Field(default=3.5, ge=1.0, le=10.0)

    @property
    def reserved_output_tokens(self) -> int:
        return self.max_tokens

    @property
    def max_input_tokens(self) -> int:
        return max(0, self.context_window_tokens - self.reserved_output_tokens)

    @property
    def max_input_characters(self) -> int:
        return int(self.max_input_tokens * self.chars_per_token)

    def estimate_tokens(self, text: str) -> int:
        import math
        return math.ceil(len(text) / self.chars_per_token)


class AIConfig(BaseModel):
    """Central configuration for the LogIntel AI subsystem."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(default=True)
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    max_concurrent_generations: int = Field(default=1, ge=1, le=8)
    concurrency_timeout_seconds: float = Field(default=0.0, ge=0.0, le=60.0)
    max_response_bytes: int = Field(default=1048576, ge=4096, le=10485760)  # 1 MB default, 10 MB max
    max_context_bytes: int = Field(default=2097152, ge=4096, le=20971520)  # 2 MB default
    allow_remote_endpoints: bool = Field(default=False)

