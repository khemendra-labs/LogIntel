"""LogIntel AI Subsystem (Milestones 5.1 & 5.2).

Defines typed domain contracts, epistemic models, citation manifests,
deterministic context assembly, and local-only AI runtime integrations.
"""

from logintel.ai.config import AIConfig, AIProviderType, EndpointValidator, ModelConfig, ProviderConfig
from logintel.ai.context.assembler import InvestigationContextAssembler
from logintel.ai.context.budget import ContextBudget
from logintel.ai.context.serializer import ContextSerializer
from logintel.ai.domain.citation import Citation, CitationManifest
from logintel.ai.domain.context import ContextTier, InvestigationContext, TruncationMetadata
from logintel.ai.domain.epistemic import EpistemicStatus
from logintel.ai.domain.evidence import EvidenceRef, EvidenceTrustLevel, EvidenceType, UntrustedTelemetryPayload
from logintel.ai.domain.provider import LocalAIProvider, ProviderCapabilities, ProviderHealth, ProviderResult
from logintel.ai.domain.response import AIInvestigationResponse, CitationRef, Claim
from logintel.ai.errors import (
    AIConcurrencyLimit,
    AIError,
    AIRequestCancelled,
    CrossInvestigationCitation,
    InvalidCitation,
    InvalidEpistemicClaim,
    ModelUnavailable,
    ProviderMalformedResponse,
    ProviderResponseTooLarge,
    ProviderTimeout,
    ProviderUnavailable,
    UnsafeProviderEndpoint,
)
from logintel.ai.parser import ResponseParser
from logintel.ai.provider.mock import MockAIProvider
from logintel.ai.provider.ollama import OllamaProvider
from logintel.ai.request import RequestBuilder
from logintel.ai.service import AIAuditEntry, AIService, SessionState, ai_service

__all__ = [
    # M5.1 Core
    "EpistemicStatus",
    "EvidenceType",
    "EvidenceTrustLevel",
    "EvidenceRef",
    "UntrustedTelemetryPayload",
    "Citation",
    "CitationManifest",
    "Claim",
    "CitationRef",
    "AIInvestigationResponse",
    "LocalAIProvider",
    "ProviderCapabilities",
    "ProviderHealth",
    "ProviderResult",
    "ContextTier",
    "TruncationMetadata",
    "InvestigationContext",
    "InvestigationContextAssembler",
    "ContextSerializer",
    "ContextBudget",
    # M5.2 Runtime & Integration
    "AIConfig",
    "ProviderConfig",
    "ModelConfig",
    "AIProviderType",
    "EndpointValidator",
    "OllamaProvider",
    "MockAIProvider",
    "RequestBuilder",
    "ResponseParser",
    "AIService",
    "ai_service",
    "SessionState",
    "AIAuditEntry",
    # M5.2 Errors
    "AIError",
    "ProviderUnavailable",
    "ModelUnavailable",
    "ProviderTimeout",
    "ProviderMalformedResponse",
    "ProviderResponseTooLarge",
    "InvalidCitation",
    "CrossInvestigationCitation",
    "InvalidEpistemicClaim",
    "UnsafeProviderEndpoint",
    "AIConcurrencyLimit",
    "AIRequestCancelled",
]
