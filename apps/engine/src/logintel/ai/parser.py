"""Response Extraction, Schema Validation, Epistemic Verification, and Citation Enforcement for LogIntel M5.2."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import ValidationError

from logintel.ai.domain.citation import CitationManifest
from logintel.ai.domain.epistemic import EpistemicStatus
from logintel.ai.domain.provider import ProviderResult
from logintel.ai.domain.response import AIInvestigationResponse, Claim, CitationRef
from logintel.ai.errors import (
    CrossInvestigationCitation,
    InvalidCitation,
    InvalidEpistemicClaim,
    ProviderMalformedResponse,
)
from logintel.logging import get_logger

logger = get_logger("ai.parser")


class ResponseParser:
    """Parses untrusted model output into a strictly validated, evidence-grounded response."""

    @classmethod
    def clean_json_text(cls, raw_output: str) -> str:
        """Strip markdown fences and whitespace to extract raw JSON payload."""
        text = raw_output.strip()
        # Handle ```json ... ``` markdown enclosures
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if match:
            text = match.group(1).strip()
        else:
            # If model returned introductory commentary, find outermost balanced JSON braces
            first_brace = text.find("{")
            last_brace = text.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                text = text[first_brace : last_brace + 1].strip()
        return text

    @classmethod
    def parse_and_validate(
        cls,
        result: ProviderResult,
        manifest: CitationManifest,
        strict_citations: bool = True,
        investigation_id: Optional[int] = None,
        known_global_citations: Optional[Set[str]] = None,
        global_checker: Optional[Any] = None,
    ) -> AIInvestigationResponse:
        """Parse raw model output, validate schema, verify epistemic invariants, and enforce citation boundaries."""
        cleaned_text = cls.clean_json_text(result.raw_output)

        if not cleaned_text:
            raise ProviderMalformedResponse(
                "Model produced empty or whitespace-only completion",
                details={"raw_length": len(result.raw_output)},
            )

        try:
            parsed_dict = json.loads(cleaned_text)
        except Exception as e:
            raise ProviderMalformedResponse(
                f"Failed to parse model output as valid JSON: {str(e)}",
                details={"snippet": cleaned_text[:200], "error": str(e)},
            ) from e

        if not isinstance(parsed_dict, dict):
            raise ProviderMalformedResponse(
                "Model output parsed as JSON but root entity is not a dictionary object",
                details={"type": type(parsed_dict).__name__},
            )

        # Validate with Pydantic
        try:
            response = AIInvestigationResponse.model_validate(parsed_dict)
        except ValidationError as e:
            err_msg = str(e)
            if any(term in err_msg for term in ["OBSERVED claims", "INFERRED claims", "UNKNOWN assertions", "epistemic"]):
                raise InvalidEpistemicClaim(
                    f"Model claim violated epistemic contract constraints: {err_msg}",
                    details={"validation_errors": e.errors()},
                ) from e
            raise ProviderMalformedResponse(
                f"Model response failed Pydantic schema validation: {str(e)}",
                details={"validation_errors": e.errors()},
            ) from e

        # Epistemic invariant validation across all claims
        for idx, claim in enumerate(response.claims):
            if claim.status == EpistemicStatus.OBSERVED:
                if not claim.evidence_refs:
                    raise InvalidEpistemicClaim(
                        f"Claim {idx} is marked OBSERVED but provides zero evidence references: '{claim.claim_text}'",
                        details={"claim_index": idx, "claim_text": claim.claim_text},
                    )
            elif claim.status == EpistemicStatus.INFERRED:
                if not claim.evidence_refs:
                    raise InvalidEpistemicClaim(
                        f"Claim {idx} is marked INFERRED but provides zero evidence references: '{claim.claim_text}'",
                        details={"claim_index": idx, "claim_text": claim.claim_text},
                    )
                if not claim.rationale or not claim.rationale.strip():
                    raise InvalidEpistemicClaim(
                        f"Claim {idx} is marked INFERRED but lacks an explicit analytical rationale: '{claim.claim_text}'",
                        details={"claim_index": idx, "claim_text": claim.claim_text},
                    )
            elif claim.status == EpistemicStatus.UNKNOWN:
                if claim.evidence_refs:
                    raise InvalidEpistemicClaim(
                        f"Claim {idx} is marked UNKNOWN but incorrectly attaches evidence references: '{claim.claim_text}'",
                        details={"claim_index": idx, "claim_text": claim.claim_text},
                    )

        # Authoritative Citation Manifest boundary enforcement
        unverified_citations: List[str] = []
        cited_tags: Set[str] = set()

        # Collect citations from response citations list
        for cit in response.citations:
            cited_tags.add(cit.citation_tag)

        # Collect citations embedded in claim evidence_refs
        for claim in response.claims:
            for ref in claim.evidence_refs:
                cited_tags.add(ref.citation_tag)

        def _get_tag(r: Any) -> Optional[str]:
            if isinstance(r, str):
                return r
            if isinstance(r, dict):
                return r.get("citation_tag") or r.get("tag")
            return getattr(r, "citation_tag", None)

        # Collect citations from hypotheses (M5.3)
        for hyp in response.hypotheses:
            for ref in hyp.supporting_evidence:
                t = _get_tag(ref)
                if t:
                    cited_tags.add(t)
            for ref in hyp.contradicting_evidence:
                t = _get_tag(ref)
                if t:
                    cited_tags.add(t)

        # Collect citations from conflicts (M5.3)
        for conf in response.conflicts:
            if conf.evidence_tag_a:
                cited_tags.add(conf.evidence_tag_a)
            if conf.evidence_tag_b:
                cited_tags.add(conf.evidence_tag_b)

        # Invariant enforcement: AI never executes queries
        for qp in response.suggested_query_proposals:
            qp.is_executed = False

        # Validate each citation against the context manifest
        for tag in cited_tags:
            if not manifest.is_citation_valid(tag):
                unverified_citations.append(tag)
                if strict_citations:
                    # Distinguish cross-investigation vs invalid citation
                    if global_checker is not None and callable(global_checker):
                        is_cross = bool(global_checker(tag))
                    elif known_global_citations is not None:
                        is_cross = tag in known_global_citations
                    else:
                        is_cross = (":" in tag)

                    if is_cross:
                        raise CrossInvestigationCitation(
                            f"Model response cited evidence '{tag}' which exists globally but is not present in this investigation context",
                            details={"invalid_citation": tag, "investigation_id": investigation_id},
                        )
                    else:
                        raise InvalidCitation(
                            f"Model response cited invalid or unknown evidence tag '{tag}'",
                            details={"invalid_citation": tag, "investigation_id": investigation_id},
                        )

        # Update verification tracking flags
        has_unverified = len(unverified_citations) > 0
        response.has_unverified_claims = has_unverified
        response.unverified_citations = unverified_citations
        response.model_identifier = f"{result.provider_id}:{result.model_id}"

        # Attach immutable non-authoritative forensic metadata
        response.metadata.update({
            "is_authoritative": False,
            "classification": "NON_AUTHORITATIVE_ANALYTICAL_OUTPUT",
            "request_id": result.request_id,
            "provider_id": result.provider_id,
            "runtime_version": result.runtime_version,
            "model_id": result.model_id,
            "model_digest": result.model_digest,
            "latency_ms": result.latency_ms,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "termination_reason": result.termination_reason,
            "investigation_id": investigation_id,
        })

        return response
