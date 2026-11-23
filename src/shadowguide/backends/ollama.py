"""Local backend: an Ollama server on this machine (loopback only)."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Backend, BackendError, validate_model
from .http import request_json, validate_url

DEFAULT_URL = "http://127.0.0.1:11434"


class OllamaBackend(Backend):
    name = "ollama"
    is_local = True

    def __init__(self, model: Optional[str] = None, host: str = DEFAULT_URL, timeout: float = 180.0):
        self.host = validate_url(host, require_loopback=True)
        self.model = validate_model(model) if model else ""
        self.timeout = timeout

    @property
    def destination(self) -> str:
        return self.host

    def list_models(self) -> List[str]:
        data = request_json(self.host + "/api/tags", timeout=10)
        models = data.get("models", [])
        return [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]

    def prepare(self) -> Optional[str]:
        names = self.list_models()
        if not self.model:
            if not names:
                raise BackendError("Ollama is running but has no models. Install one, for example: ollama pull llama3.2")
            self.model = names[0]
            return "Using the Ollama model '{}'. Choose another with --model.".format(self.model)
        if self.model not in names and self.model + ":latest" not in names:
            available = ", ".join(names) if names else "none installed"
            raise BackendError("Model '{}' is not installed in Ollama (available: {}). Run: ollama pull {}".format(
                self.model, available, self.model))
        return None

    def generate(self, system: str, messages: List[Dict[str, str]]) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2, "num_predict": 2048},
        }
        data = request_json(self.host + "/api/chat", payload, timeout=self.timeout)
        content = (data.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise BackendError("Ollama returned an unexpected reply.")
        return content
