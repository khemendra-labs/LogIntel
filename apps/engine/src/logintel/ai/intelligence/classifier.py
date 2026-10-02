"""Deterministic Question and Intent Classification for LogIntel Milestone 5.3.

Classifies natural language analyst inquiries into structured investigation intents
and extracts referenced entities or temporal bounds without executing arbitrary AI logic.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from logintel.ai.domain.intelligence import InvestigationIntent


INTENT_PATTERNS = [
    (
        InvestigationIntent.TIMELINE,
        re.compile(r"\b(timeline|chronolog\w*|sequence|order of events|what happened (before|after|first|then))\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.ATTACK_PATH_EXPLANATION,
        re.compile(r"\b(attack path|progression|kill chain|attack steps|lateral movement path)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.MITRE_EXPLANATION,
        re.compile(r"\b(mitre|att&ck|technique|tactic|t\d{4}(\.\d{3})?)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.ALERT_EXPLANATION,
        re.compile(r"\b(why was\s+(?:the|this|an?)?\s*alert|alert\s+explanation|explain\s+(?:the|this|an?)?\s*alert|alert\s+details)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.EVIDENCE_EXPLANATION,
        re.compile(r"\b(evidence\s+(?:details|explanation)|explain\s+(?:the\s+)?evidence|what does this evidence mean|explain\s+event\b)", re.IGNORECASE),
    ),
    (
        InvestigationIntent.DETECTION_EXPLANATION,
        re.compile(r"\b(detection\s+rule|why did\s+(?:the|this)\s+rule trigger|rule\s+logic|explain\s+detection)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.EVIDENCE_GAP,
        re.compile(r"\b(missing|gap|blind spot|visibility|what don'?t we know|unobserved|unanswered)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.HYPOTHESIS,
        re.compile(r"\b(could (this|it) be|hypothesis|theor(y|ize)|is it possible|plausible|suspect)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.NEXT_QUERY,
        re.compile(r"\b(next\s+(?:query|queries|step|steps)|queries\s+.*?\bnext\b|threat\s+hunting|hunt(?:ing)?\s+query|what should\s+(?:we|i)\s+(?:search|run)|pivot\s+next)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.ENTITY_ANALYSIS,
        re.compile(r"\b(activity\s+(?:was\s+)?observed|who is|what is known about|investigate\s+(?:user|host|ip|process)|entity\s+pivot)\b", re.IGNORECASE),
    ),
    (
        InvestigationIntent.SUMMARY,
        re.compile(r"\b(summar(y|ize)|what happened|overview|briefing|executive summary)\b", re.IGNORECASE),
    ),
]

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class QuestionClassifier:
    """Deterministic intent classifier for analyst inquiries."""

    @classmethod
    def classify(cls, question: str) -> Tuple[InvestigationIntent, Optional[str]]:
        """Classify an analyst question into an InvestigationIntent and extract any target entity.
        
        Returns:
            Tuple of (InvestigationIntent, Optional[target_entity_string])
        """
        text = question.strip()
        if not text:
            return InvestigationIntent.SUMMARY, None

        # Check entity extraction (e.g. IP address or explicitly tagged / named entity)
        target_entity: Optional[str] = None
        ip_match = IPV4_REGEX.search(text)
        if ip_match:
            target_entity = f"ip:{ip_match.group(0)}"
        else:
            # Check for user[: ]<name> or host[: ]<name> or process[: ]<name>
            ent_match = re.search(r"\b(user|host|process)[\s:]+([a-zA-Z0-9_.-]+)\b", text, re.IGNORECASE)
            if ent_match:
                prefix = ent_match.group(1).lower()
                val = ent_match.group(2)
                # Avoid capturing verbs as names (e.g., 'host was')
                if val.lower() not in {"was", "is", "were", "did", "activity"}:
                    target_entity = f"{prefix}:{val}"

        # Match against deterministic intent regexes
        for intent, pattern in INTENT_PATTERNS:
            if pattern.search(text):
                # If question specifically focuses on an entity and target is present, prioritize ENTITY_ANALYSIS
                if target_entity and intent in (InvestigationIntent.SUMMARY, InvestigationIntent.GENERAL):
                    return InvestigationIntent.ENTITY_ANALYSIS, target_entity
                return intent, target_entity

        # Fallback: if an entity is identified, default to ENTITY_ANALYSIS; otherwise GENERAL
        if target_entity:
            return InvestigationIntent.ENTITY_ANALYSIS, target_entity

        return InvestigationIntent.GENERAL, None

