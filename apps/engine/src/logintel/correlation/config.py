"""Configuration settings for LogIntel Incident Correlation Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CorrelationConfig(BaseModel):
    """Runtime configuration parameters for deterministic incident correlation."""

    window_seconds: int = Field(
        default=1800,  # 30-minute default correlation window
        description="Maximum seconds elapsed between alerts to correlate into the same incident.",
    )
    max_incident_duration_seconds: int = Field(
        default=86400,  # 24-hour maximum duration per incident
        description="Maximum span between first_seen and last_seen before forcing a new incident rollover.",
    )
    cross_host_correlation: bool = Field(
        default=True,
        description="Enable multi-host correlation when the same attacker IP or user account pivots across hosts.",
    )
    multi_stage_escalation: bool = Field(
        default=True,
        description="Elevate incident severity when correlated alerts span multiple cyber kill-chain categories.",
    )
    min_alerts_for_multi_stage: int = Field(
        default=2,
        description="Minimum alerts required across distinct categories to trigger multi-stage escalation.",
    )
