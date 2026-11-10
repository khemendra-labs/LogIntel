"""Low-footprint remote collector agent primitives."""

from logintel.agent.client import FleetClient
from logintel.agent.config import AgentConfig
from logintel.agent.spool import JsonlSpool

__all__ = ["AgentConfig", "FleetClient", "JsonlSpool"]
