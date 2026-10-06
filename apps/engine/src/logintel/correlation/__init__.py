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

from logintel.identity import (
    AuditIdentity,
    IdentityContinuityChain,
    PrivilegeTransition,
    PrivilegeTransitionType,
    SessionContinuityResolver,
    SessionRecord,
    SessionState,
)

__all__ = [
    "AttackStage",
    "AuditIdentity",
    "CATEGORY_TO_STAGE",
    "CorrelationConfig",
    "IdentityContinuityChain",
    "IncidentCorrelationEngine",
    "PrivilegeTransition",
    "PrivilegeTransitionType",
    "ProcessAncestryChain",
    "ProcessAncestryResolver",
    "ProcessNode",
    "SCENARIO_SIGNATURES",
    "SessionContinuityResolver",
    "SessionRecord",
    "SessionState",
    "build_process_identity",
    "classify_stages",
    "correlation_engine",
    "evaluate_escalation",
]
