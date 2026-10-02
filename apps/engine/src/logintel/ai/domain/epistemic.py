"""Epistemic classification models for LogIntel AI assistance.

Formally distinguishes directly observed forensic facts from analytical inferences
and acknowledged unknowns.
"""

from __future__ import annotations

from enum import Enum


class EpistemicStatus(str, Enum):
    """Epistemic status of a claim, step, or narrative statement.
    
    OBSERVED: Directly supported by persisted canonical log events, verified alerts,
              or detected rule hits.
    INFERRED: Analytical hypothesis or deduction derived from evidence, requiring
              explicit supporting citations and reasoning.
    UNKNOWN: Acknowledged absence of evidence, unmonitored behavior, or indeterminate state.
             Must NEVER be converted into an affirmative true or false fact.
    """

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value
