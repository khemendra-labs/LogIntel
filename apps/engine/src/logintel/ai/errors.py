"""LogIntel M5.2 Local AI Runtime Exceptions and Error Contracts.

Defines structured exception types for provider failures, validation errors,
security boundary violations, and resource constraints without leaking credentials
or sensitive evidence payloads.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class AIError(Exception):
    """Base exception for all LogIntel AI subsystem operations."""

    def __init__(
        self,
        message: str,
        error_code: str = "AI_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class ProviderUnavailable(AIError):
    """Raised when the local AI runtime daemon/binary cannot be reached or is not running."""

    def __init__(self, message: str = "Local AI runtime is unavailable", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="PROVIDER_UNAVAILABLE", details=details)


class ModelUnavailable(AIError):
    """Raised when the requested model is not installed or cannot be loaded by the local runtime."""

    def __init__(self, message: str = "Configured model is not installed or available", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="MODEL_UNAVAILABLE", details=details)


class ProviderTimeout(AIError):
    """Raised when local AI generation exceeds the configured deadline."""

    def __init__(self, message: str = "Local AI inference request timed out", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="PROVIDER_TIMEOUT", details=details)


class ProviderMalformedResponse(AIError):
    """Raised when the local AI model produces unparseable JSON or violates the required schema."""

    def __init__(self, message: str = "Model returned malformed or unparseable output", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="PROVIDER_MALFORMED_RESPONSE", details=details)


class ProviderResponseTooLarge(AIError):
    """Raised when the response from the provider exceeds the safety byte limit."""

    def __init__(self, message: str = "Model response exceeded maximum allowed payload size", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="PROVIDER_RESPONSE_TOO_LARGE", details=details)


class InvalidCitation(AIError):
    """Raised when a model response contains an invalid or malformed citation tag."""

    def __init__(self, message: str = "Model cited an invalid or unknown evidence identifier", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="INVALID_CITATION", details=details)


class CrossInvestigationCitation(InvalidCitation):
    """Raised when a model response attempts to cite evidence from another investigation context."""

    def __init__(self, message: str = "Model cited evidence not present in current investigation context", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, details=details)
        self.error_code = "CROSS_INVESTIGATION_CITATION"


class InvalidEpistemicClaim(AIError):
    """Raised when a model claim violates M5.1 epistemic invariants (e.g. OBSERVED without evidence)."""

    def __init__(self, message: str = "Model claim violated epistemic contract constraints", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="INVALID_EPISTEMIC_CLAIM", details=details)


class UnsafeProviderEndpoint(AIError):
    """Raised when a provider endpoint URL targets a non-local or unapproved network destination."""

    def __init__(self, message: str = "Provider endpoint violates local-only network security policy", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="UNSAFE_PROVIDER_ENDPOINT", details=details)


class AIConcurrencyLimit(AIError):
    """Raised when maximum concurrent AI generation requests are exceeded."""

    def __init__(self, message: str = "Maximum concurrent AI generation requests reached", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="CONCURRENCY_LIMIT_EXCEEDED", details=details)


class AIRequestCancelled(AIError):
    """Raised when an ongoing AI generation request is cancelled by the caller or runtime."""

    def __init__(self, message: str = "AI generation request was cancelled", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="REQUEST_CANCELLED", details=details)


class ContextBudgetExceeded(AIError):
    """Raised when an assembled context or request exceeds the model's effective context window."""

    def __init__(self, message: str = "Request exceeds model effective context budget", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="CONTEXT_BUDGET_EXCEEDED", details=details)

