"""Citation and citation manifest models for LogIntel AI assistance.

Maintains an immutable inventory of verified evidence citations available
within a specific investigation context packet, and validates model output citations.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.evidence import EvidenceType

# Standard bracketed citation tag regex: matches [category:id], e.g. [event:evt-101], [entity:ip:192.168.1.1], [database:123]
CITATION_TAG_REGEX = re.compile(r"\[([a-zA-Z0-9_-]+):([^\]\s]+)\]")
VALID_EVIDENCE_TYPE_STRINGS: Set[str] = {t.value for t in EvidenceType}


class Citation(BaseModel):
    """An individual verified evidence citation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_type: EvidenceType
    evidence_id: str
    canonical_tag: str
    display_label: str

    @classmethod
    def create(
        cls,
        evidence_type: EvidenceType,
        evidence_id: str,
        display_label: Optional[str] = None,
    ) -> Citation:
        clean_id = evidence_id.strip()
        tag = f"[{evidence_type.value}:{clean_id}]"
        label = display_label or f"{evidence_type.value.capitalize()} {clean_id}"
        return cls(
            evidence_type=evidence_type,
            evidence_id=clean_id,
            canonical_tag=tag,
            display_label=label,
        )


class CitationManifest(BaseModel):
    """Inventory of all valid, authoritative evidence references within a context packet."""

    model_config = ConfigDict(extra="forbid")

    citations: Dict[str, Citation] = Field(default_factory=dict)

    def add(
        self,
        evidence_type: EvidenceType,
        evidence_id: str,
        display_label: Optional[str] = None,
    ) -> Citation:
        """Register a citation in the manifest. Existing tags are deduplicated."""
        cit = Citation.create(evidence_type, evidence_id, display_label)
        self.citations[cit.canonical_tag] = cit
        return cit

    def get(self, tag: str) -> Optional[Citation]:
        return self.citations.get(tag)

    def contains(self, tag: str) -> bool:
        return tag in self.citations

    def tags(self) -> List[str]:
        """Return deterministically sorted list of all citation tags."""
        return sorted(self.citations.keys())

    def validate_citations(self, text: str) -> Tuple[List[Citation], List[str]]:
        """Extract bracketed citations from text and partition into valid vs ungrounded/invalid tags.
        
        A tag is valid ONLY if its category is a recognized EvidenceType AND its tag
        exists within this authoritative investigation CitationManifest.
        Any unknown tag or invalid category (e.g. [database:123], [event:unknown])
        is partitioned into the invalid tags list.
        
        Returns:
            Tuple of (valid_citations_list, invalid_tags_list)
        """
        valid: List[Citation] = []
        invalid: List[str] = []
        seen: Set[str] = set()

        for match in CITATION_TAG_REGEX.finditer(text):
            tag = match.group(0)
            category = match.group(1).lower()
            if tag in seen:
                continue
            seen.add(tag)

            if category in VALID_EVIDENCE_TYPE_STRINGS and tag in self.citations:
                valid.append(self.citations[tag])
            else:
                invalid.append(tag)

        # Sort deterministically
        valid.sort(key=lambda c: c.canonical_tag)
        invalid.sort()
        return valid, invalid
