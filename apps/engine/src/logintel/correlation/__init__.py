from logintel.correlation.ancestry import (
    ProcessAncestryChain,
    ProcessAncestryResolver,
    ProcessNode,
    build_process_identity,
)
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
    "ProcessAncestryChain",
    "ProcessAncestryResolver",
    "ProcessNode",
    "SCENARIO_SIGNATURES",
    "build_process_identity",
    "classify_stages",
    "correlation_engine",
    "evaluate_escalation",
]
