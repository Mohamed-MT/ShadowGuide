"""Model backends: local Ollama, or the user's own API key (OpenAI-compatible or Anthropic)."""
from __future__ import annotations

from typing import Optional

from .anthropic import DEFAULT_BASE as ANTHROPIC_DEFAULT_BASE, AnthropicBackend
from .base import Backend, BackendError, Secret
from .ollama import DEFAULT_URL, OllamaBackend
from .openai_compat import DEFAULT_BASE as OPENAI_DEFAULT_BASE, OpenAICompatBackend

BACKEND_CHOICES = ("ollama", "openai", "anthropic")


def create_backend(name: str, model: Optional[str], host: str = DEFAULT_URL,
                   base_url: Optional[str] = None, key: Optional[Secret] = None) -> Backend:
    if name == "ollama":
        return OllamaBackend(model=model, host=host)
    if not model:
        raise BackendError("Cloud backends need a model name: --model <name> (or set SHADOWGUIDE_MODEL).")
    if name == "openai":
        return OpenAICompatBackend(model=model, key=key, base_url=base_url or OPENAI_DEFAULT_BASE)
    if name == "anthropic":
        return AnthropicBackend(model=model, key=key, base_url=base_url or ANTHROPIC_DEFAULT_BASE)
    raise BackendError("Unknown backend '{}'.".format(name))


__all__ = ["ANTHROPIC_DEFAULT_BASE", "BACKEND_CHOICES", "DEFAULT_URL", "OPENAI_DEFAULT_BASE", "Backend", "BackendError",
           "Secret", "create_backend"]
