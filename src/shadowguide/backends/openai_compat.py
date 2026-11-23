"""Cloud (or self-hosted) backend for any OpenAI-compatible chat completions API."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Backend, BackendError, Secret, validate_model
from .http import is_loopback_url, request_json, validate_url
from urllib.parse import urlparse

DEFAULT_BASE = "https://api.openai.com/v1"


class OpenAICompatBackend(Backend):
    name = "openai"

    def __init__(self, model: str, key: Optional[Secret], base_url: str = DEFAULT_BASE, timeout: float = 120.0):
        self.base_url = validate_url(base_url)
        self.is_local = is_loopback_url(self.base_url)
        if key is None and not self.is_local:
            raise BackendError("An API key is required for this endpoint.")
        self.model = validate_model(model)
        self._key = key
        self.timeout = timeout

    @property
    def destination(self) -> str:
        return urlparse(self.base_url).hostname or "unknown host"

    def generate(self, system: str, messages: List[Dict[str, str]]) -> str:
        headers = {"Authorization": "Bearer " + self._key.reveal()} if self._key else {}
        payload = {"model": self.model, "messages": [{"role": "system", "content": system}, *messages]}
        data = request_json(self.base_url + "/chat/completions", payload, headers, self.timeout)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise BackendError("The provider returned an unexpected reply.") from None
        if isinstance(content, list):  # some providers return content parts
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        if not isinstance(content, str):
            raise BackendError("The provider returned an unexpected reply.")
        return content
