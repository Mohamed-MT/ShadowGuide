"""Cloud backend for Anthropic's Messages API."""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

from .base import Backend, BackendError, Secret, validate_model
from .http import is_loopback_url, request_json, validate_url

DEFAULT_BASE = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicBackend(Backend):
    name = "anthropic"

    def __init__(self, model: str, key: Secret | None, base_url: str = DEFAULT_BASE, timeout: float = 120.0):
        if key is None:
            raise BackendError("An API key is required.")
        self.base_url = validate_url(base_url)
        self.is_local = is_loopback_url(self.base_url)
        self.model = validate_model(model)
        self._key = key
        self.timeout = timeout

    @property
    def destination(self) -> str:
        return urlparse(self.base_url).hostname or "unknown host"

    def generate(self, system: str, messages: List[Dict[str, str]]) -> str:
        headers = {"x-api-key": self._key.reveal(), "anthropic-version": API_VERSION}
        payload = {"model": self.model, "max_tokens": 2048, "system": system, "messages": messages}
        data = request_json(self.base_url + "/v1/messages", payload, headers, self.timeout)
        blocks = data.get("content")
        if not isinstance(blocks, list):
            raise BackendError("The provider returned an unexpected reply.")
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
        if not text:
            raise BackendError("The provider returned an empty reply.")
        return text
