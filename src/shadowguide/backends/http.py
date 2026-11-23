"""The single network egress point for the whole application.

Every outbound request goes through request_json(), which enforces the URL policy
itself (it never trusts its callers). A test enforces that no other module imports
network libraries. Rules enforced here:
- https required, except for loopback addresses; no other schemes (no file:, ftp:)
- no credentials embedded in URLs
- redirects are refused (urllib would otherwise forward auth headers to the new host)
- TLS 1.2 or newer with certificate verification
- loopback requests ignore system proxy settings
- response size is capped, and a total deadline stops slow-drip responses
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..sanitize import redact, strip_unsafe
from .base import BackendError

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
LOOPBACK_HOSTS = frozenset(("127.0.0.1", "localhost", "::1"))
_CHUNK = 64 * 1024


def is_loopback_url(url: str) -> bool:
    try:
        return urlparse(url).hostname in LOOPBACK_HOSTS
    except ValueError:
        return False


def validate_url(url: str, require_loopback: bool = False) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        raise BackendError("That URL is not valid.") from None
    if parsed.scheme not in ("http", "https") or not host:
        raise BackendError("URLs must start with https:// (or http:// for localhost).")
    if parsed.username or parsed.password:
        raise BackendError("URLs that contain credentials are not accepted.")
    loopback = host in LOOPBACK_HOSTS
    if require_loopback and not loopback:
        raise BackendError("This backend only talks to a server on this machine (127.0.0.1, localhost or ::1).")
    if parsed.scheme == "http" and not loopback:
        raise BackendError("Plain http is only allowed for localhost. Use https.")
    return url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _opener(local: bool) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    handlers: list[Any] = [_NoRedirect(), urllib.request.HTTPSHandler(context=ctx)]
    if local:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def _provider_message(exc: urllib.error.HTTPError) -> str:
    try:
        data = json.loads(exc.read(4096).decode("utf-8", "replace"))
        err = data.get("error", data) if isinstance(data, dict) else {}
        msg = err.get("message") if isinstance(err, dict) else str(err)
    except (ValueError, RecursionError, OSError, AttributeError):
        return ""
    if not isinstance(msg, str):
        return ""
    return redact(strip_unsafe(msg))[0].replace("\n", " ")[:200]


def _describe_http_error(exc: urllib.error.HTTPError) -> str:
    code = exc.code
    if code in (401, 403):
        return f"The server rejected the API key (HTTP {code}). Check that the key is valid and can use this model."
    if code == 404:
        return "Not found (HTTP 404). Check the model name and endpoint URL."
    if code == 429:
        return "Rate limit or quota reached (HTTP 429). Wait a bit, or check your plan."
    if 300 <= code < 400:
        return f"The server tried to redirect the request (HTTP {code}). Redirects are refused for safety."
    detail = _provider_message(exc)
    return f"The server returned HTTP {code}." + (" " + detail if detail else "")


def _read_limited(resp: Any, deadline: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise BackendError("The server took too long to finish its reply.")
        chunk = resp.read1(_CHUNK)  # read1 returns as soon as any data arrives, so the deadline is checked often
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise BackendError("The response was larger than the safety limit and was discarded.")
        chunks.append(chunk)


def request_json(url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None,
                 timeout: float = 120.0) -> dict[str, Any]:
    url = validate_url(url)  # enforce policy here too; never rely on callers
    local = is_loopback_url(url)
    host = urlparse(url).hostname or "server"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "shadowguide"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST" if data is not None else "GET")  # noqa: S310
    deadline = time.monotonic() + timeout
    try:
        with _opener(local).open(req, timeout=timeout) as resp:  # scheme validated above
            raw = _read_limited(resp, deadline)
    except urllib.error.HTTPError as exc:
        try:
            message = _describe_http_error(exc)
        finally:
            exc.close()  # an HTTPError keeps its connection open until closed
        raise BackendError(message) from None
    except (urllib.error.URLError, OSError, ValueError):
        hint = " Is it installed and running? (https://ollama.com)" if local else ""
        raise BackendError(f"Could not connect to {host}.{hint}") from None
    try:
        result = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise BackendError("The server sent a reply that is not valid JSON.") from None
    if not isinstance(result, dict):
        raise BackendError("The server sent an unexpected reply.")
    return result
