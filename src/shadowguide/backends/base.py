"""Backend interface and shared safety primitives."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Dict, List, NoReturn, Optional

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,99}$")
_KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")


class BackendError(RuntimeError):
    """A user-presentable error. Messages must never contain secrets."""


class Secret:
    """Holds an API key in memory only. Never printed, logged, pickled or stored."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not _KEY_RE.fullmatch(value or ""):
            # Printable ASCII only: blocks header injection through CR/LF and spaces.
            raise BackendError("The API key has an unexpected format (it must be 8-512 printable characters "
                               "with no spaces or line breaks).")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be serialized")


def validate_model(name: Optional[str]) -> str:
    if not name or not _MODEL_RE.fullmatch(name):
        raise BackendError("Invalid model name. Use letters, digits and . _ : / @ - only.")
    return name


class Backend(ABC):
    name: str = ""
    is_local: bool = True
    model: str = ""

    @property
    @abstractmethod
    def destination(self) -> str:
        """Human-readable place where questions are sent (host only, never a key)."""

    @abstractmethod
    def generate(self, system: str, messages: List[Dict[str, str]]) -> str:
        """Return the model's text reply. Must not execute or write anything."""

    def list_models(self) -> List[str]:
        return []

    def prepare(self) -> Optional[str]:
        """Validate configuration without leaving the machine. Returns an optional note."""
        return None

    def describe(self) -> str:
        where = "local" if self.is_local else "cloud"
        return "{} ({}) model: {}".format(self.name, where, self.model or "auto")
