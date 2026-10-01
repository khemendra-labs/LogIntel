"""LogIntel Incident Correlation and Attack Graph Synthesis package."""

from logintel.correlation.config import CorrelationConfig
from logintel.correlation.engine import IncidentCorrelationEngine, correlation_engine
from logintel.correlation.scenarios import (
    AttackStage,
    CATEGORY_TO_STAGE,
    SCENARIO_SIGNATURES,
    classify_stages,
    evaluate_escalation,
)

__all__ = [
    "AttackStage",
    "CATEGORY_TO_STAGE",
    "CorrelationConfig",
    "IncidentCorrelationEngine",
    "SCENARIO_SIGNATURES",
    "classify_stages",
    "correlation_engine",
    "evaluate_escalation",
]
