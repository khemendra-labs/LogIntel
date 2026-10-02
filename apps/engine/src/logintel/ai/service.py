"""Local AI Service Orchestration for LogIntel M5.2.

Coordinates deterministic context assembly, provider invocation, schema validation,
ephemeral session isolation, concurrency limiting, and audit logging.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from logintel.ai.config import AIConfig, AIProviderType
from logintel.ai.context.assembler import InvestigationContextAssembler
from logintel.ai.domain.provider import LocalAIProvider, ProviderHealth, ProviderResult
from logintel.ai.domain.response import AIInvestigationResponse
from logintel.ai.errors import (
    AIConcurrencyLimit,
    AIError,
    AIRequestCancelled,
    ContextBudgetExceeded,
    ModelUnavailable,
    ProviderUnavailable,
)
from logintel.ai.parser import ResponseParser
from logintel.ai.provider.mock import MockAIProvider
from logintel.ai.provider.ollama import OllamaProvider
from logintel.ai.request import ModelContextBudgetGuard, RequestBuilder
from logintel.logging import get_logger
from logintel.storage.db import Database, db as default_db

logger = get_logger("ai.service")


class SessionMessage(BaseModel):
    """Ephemeral in-memory message representation."""

    role: str
    content: str
    timestamp: str


class SessionState(BaseModel):
    """Ephemeral conversation session state scoped strictly to (user_id, incident_id, session_id)."""

    session_id: str
    incident_id: int
    user_id: str
    created_at: str
    last_accessed_at: str
    messages: List[SessionMessage] = Field(default_factory=list)


class AIAuditEntry(BaseModel):
    """Forensic audit record for AI subsystem execution without leaking sensitive payload content."""

    request_id: str
    timestamp: str
    incident_id: int
    user_id: str
    provider_id: str
    model_id: str
    runtime_version: Optional[str] = None
    model_digest: Optional[str] = None
    input_context_hash: str
    latency_ms: float
    output_validation_status: str
    citation_count: int
    invalid_citation_count: int
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    termination_reason: Optional[str] = None
    error_code: Optional[str] = None


class AIService:
    """Central orchestration service for local AI assistance in LogIntel."""

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        provider: Optional[LocalAIProvider] = None,
        database: Optional[Database] = None,
    ) -> None:
        self.config = config or AIConfig()
        self.database = database or default_db
        self.assembler = InvestigationContextAssembler(database=self.database)

        # Initialize provider based on configuration or injection
        if provider:
            self.provider = provider
        else:
            self.provider = self._create_provider(self.config)

        # Concurrency control: bounded concurrent generation semaphore
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_generations)

        # Ephemeral session state: memory-only, keyed by (user_id, incident_id, session_id)
        # Guarantees zero cross-incident reuse and zero persistent chat tables (no Migration 6)
        self._sessions: Dict[Tuple[str, int, str], SessionState] = {}

        # In-memory audit log ring buffer
        self._audit_log: List[AIAuditEntry] = []

    def _create_provider(self, config: AIConfig) -> LocalAIProvider:
        if config.provider.provider_type == AIProviderType.MOCK:
            return MockAIProvider(model_id=config.model.model_name)
        elif config.provider.provider_type == AIProviderType.OLLAMA:
            return OllamaProvider(
                config=config.provider,
                model_config=config.model,
                max_response_bytes=config.max_response_bytes,
            )
        else:
            raise ValueError(f"Unsupported provider type: {config.provider.provider_type}")

    def get_session(self, user_id: str, incident_id: int, session_id: Optional[str] = None) -> SessionState:
        """Retrieve or create an ephemeral session strictly scoped by user and incident."""
        sid = session_id or str(uuid.uuid4())
        key = (user_id, incident_id, sid)
        now_iso = datetime.now(timezone.utc).isoformat()
        if key not in self._sessions:
            self._sessions[key] = SessionState(
                session_id=sid,
                incident_id=incident_id,
                user_id=user_id,
                created_at=now_iso,
                last_accessed_at=now_iso,
            )
        else:
            self._sessions[key].last_accessed_at = now_iso
        return self._sessions[key]

    def clear_sessions_for_incident(self, incident_id: int) -> int:
        """Purge ephemeral session state for an incident."""
        keys_to_remove = [k for k in self._sessions.keys() if k[1] == incident_id]
        for k in keys_to_remove:
            del self._sessions[k]
        return len(keys_to_remove)

    async def get_status(self) -> Dict[str, Any]:
        """Diagnostic status of provider and model availability."""
        health = await self.provider.health_check()
        return {
            "enabled": self.config.enabled,
            "provider_id": self.provider.provider_id,
            "runtime_healthy": health.is_healthy,
            "runtime_version": health.runtime_version,
            "configured_model": self.config.model.model_name,
            "active_model": health.active_model,
            "active_model_available": health.active_model_available,
            "installed_models": health.installed_models,
            "latency_ms": health.latency_ms,
            "error": health.error,
        }

    def _is_tag_in_global_db(self, tag: str) -> bool:
        """Check whether an evidence tag corresponds to an authoritative record in global database."""
        try:
            match = re.match(r"^\[([a-zA-Z0-9_-]+):([^\]\s]+)\]$", tag)
            if not match:
                return False
            category, identifier = match.group(1).lower(), match.group(2)
            with self.database.connection() as conn:
                if category == "event":
                    row = conn.execute("SELECT 1 FROM events WHERE id = ?", (identifier,)).fetchone()
                    return row is not None
                elif category == "alert":
                    row = conn.execute("SELECT 1 FROM alerts WHERE id = ?", (identifier,)).fetchone()
                    return row is not None
                elif category == "detection":
                    row = conn.execute("SELECT 1 FROM detections WHERE id = ?", (identifier,)).fetchone()
                    return row is not None
                elif category == "incident":
                    row = conn.execute("SELECT 1 FROM incidents WHERE id = ?", (identifier,)).fetchone()
                    return row is not None
                elif category == "entity":
                    row = conn.execute("SELECT 1 FROM incident_entities WHERE entity_key = ?", (identifier,)).fetchone()
                    return row is not None
            return False
        except Exception:
            return False

    async def analyze_investigation(
        self,
        incident_id: int,
        user_id: str = "analyst",
        session_id: Optional[str] = None,
        task: Optional[str] = None,
        strict_citations: bool = True,
    ) -> AIInvestigationResponse:
        """Execute full investigation analysis pipeline for an incident."""
        if not self.config.enabled:
            raise AIError("AI subsystem is disabled in configuration", error_code="AI_DISABLED")

        req_id = f"ai-req-{uuid.uuid4().hex[:12]}"
        t_start = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Ephemeral session scoping
        session = self.get_session(user_id=user_id, incident_id=incident_id, session_id=session_id)

        # Enforce concurrency boundary
        try:
            if self.config.concurrency_timeout_seconds <= 0.0:
                if self._semaphore.locked() and self.config.max_concurrent_generations == 1:
                    raise AIConcurrencyLimit("Another AI generation request is currently executing")
                await asyncio.wait_for(self._semaphore.acquire(), timeout=0.1)
            else:
                await asyncio.wait_for(
                    self._semaphore.acquire(),
                    timeout=self.config.concurrency_timeout_seconds,
                )
        except asyncio.TimeoutError:
            raise AIConcurrencyLimit(
                f"Exceeded maximum concurrent generation wait deadline of {self.config.concurrency_timeout_seconds}s"
            )

        validation_status = "UNKNOWN"
        citation_count = 0
        invalid_citation_count = 0
        error_code = None
        result: Optional[ProviderResult] = None
        context_hash = "none"

        try:
            # 1. Deterministic Context Assembly (M5.1)
            context = self.assembler.assemble(incident_id=incident_id)
            context_hash = context.canonical_content_hash

            # 2. Deterministic Request Construction
            request_bundle = RequestBuilder.build_request(context=context, task=task)

            # 3. Model Context Budget Enforcement (M5.2-CV-002)
            ModelContextBudgetGuard.validate_request_budget(
                prompt=request_bundle["prompt"],
                system_prompt=request_bundle["system_prompt"],
                model_config=self.config.model,
            )

            # 4. Local Model Invocation
            result = await self.provider.generate(
                prompt=request_bundle["prompt"],
                system_prompt=request_bundle["system_prompt"],
                request_id=req_id,
            )

            # 5. Strict Response Parsing, Epistemic Validation, and Citation Checking
            response = ResponseParser.parse_and_validate(
                result=result,
                manifest=context.citation_manifest,
                strict_citations=strict_citations,
                investigation_id=context.investigation_id,
                global_checker=self._is_tag_in_global_db,
            )

            validation_status = "PASSED" if not response.has_unverified_claims else "UNVERIFIED_CLAIMS"
            citation_count = len(response.citations)
            invalid_citation_count = len(response.unverified_citations)

            # 5. Record Ephemeral Session History
            session.messages.append(SessionMessage(role="user", content=task or "Analyze incident", timestamp=now_iso))
            session.messages.append(SessionMessage(role="assistant", content=response.answer_markdown, timestamp=now_iso))

            return response

        except asyncio.CancelledError:
            validation_status = "CANCELLED"
            error_code = "REQUEST_CANCELLED"
            raise AIRequestCancelled("AI inference generation was cancelled")
        except AIError as e:
            validation_status = "FAILED"
            error_code = e.error_code
            raise
        except Exception as e:
            validation_status = "FAILED"
            error_code = "INTERNAL_AI_ERROR"
            raise AIError(f"Internal AI processing error: {str(e)}", error_code="INTERNAL_AI_ERROR") from e
        finally:
            self._semaphore.release()
            duration_ms = (time.perf_counter() - t_start) * 1000

            # Safe forensic audit logging (never logs passwords or raw payloads)
            audit_entry = AIAuditEntry(
                request_id=req_id,
                timestamp=now_iso,
                incident_id=incident_id,
                user_id=user_id,
                provider_id=self.provider.provider_id,
                model_id=self.provider.model_id,
                runtime_version=result.runtime_version if result else None,
                model_digest=result.model_digest if result else None,
                input_context_hash=context_hash,
                latency_ms=round(duration_ms, 2),
                output_validation_status=validation_status,
                citation_count=citation_count,
                invalid_citation_count=invalid_citation_count,
                prompt_tokens=result.prompt_tokens if result else None,
                completion_tokens=result.completion_tokens if result else None,
                termination_reason=result.termination_reason if result else None,
                error_code=error_code,
            )
            self._audit_log.append(audit_entry)
            logger.info(
                "AI Execution Audit: req=%s incident=%d status=%s latency=%.1fms error=%s",
                req_id,
                incident_id,
                validation_status,
                duration_ms,
                error_code,
            )

    def get_audit_log(self, incident_id: Optional[int] = None) -> List[AIAuditEntry]:
        """Query safe AI audit records."""
        if incident_id is not None:
            return [e for e in self._audit_log if e.incident_id == incident_id]
        return list(self._audit_log)


# Global singleton instance
ai_service = AIService()
