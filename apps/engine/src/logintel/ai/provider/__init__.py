"""Local AI inference providers package."""

from logintel.ai.provider.mock import MockAIProvider
from logintel.ai.provider.ollama import OllamaProvider

__all__ = ["OllamaProvider", "MockAIProvider"]
