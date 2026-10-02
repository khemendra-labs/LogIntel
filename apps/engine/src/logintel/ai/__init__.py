"""LogIntel AI Domain & Investigation Context Subsystem (Milestone 5.1).

Defines typed domain contracts, epistemic models, citation manifests,
and deterministic context assembly for evidence-grounded AI assistance.
"""

from logintel.ai.domain.citation import Citation, CitationManifest
from logintel.ai.domain.context import ContextTier, InvestigationContext, TruncationMetadata
from logintel.ai.domain.epistemic import EpistemicStatus
from logintel.ai.domain.evidence import EvidenceRef, EvidenceTrustLevel, EvidenceType, UntrustedTelemetryPayload
from logintel.ai.domain.provider import LocalAIProvider, ProviderCapabilities, ProviderResult
from logintel.ai.domain.response import AIInvestigationResponse, CitationRef, Claim

__all__ = [
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
    "ProviderResult",
    "ContextTier",
    "TruncationMetadata",
    "InvestigationContext",
]
