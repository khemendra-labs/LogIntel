"""Context Budget limits and configuration for InvestigationContext."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ContextBudget(BaseModel):
    """Configurable budget limits for evidence items inside an InvestigationContext."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_supporting_events: int = Field(default=25, ge=1, le=200)
    max_contextual_events: int = Field(default=25, ge=0, le=200)
    max_alerts: int = Field(default=10, ge=1, le=50)
    max_attack_path_steps: int = Field(default=10, ge=1, le=50)
    max_entities: int = Field(default=15, ge=1, le=100)
    max_relationships: int = Field(default=20, ge=0, le=100)
    max_notes: int = Field(default=10, ge=0, le=50)
    max_total_characters: int = Field(default=40000, ge=5000, le=200000)
