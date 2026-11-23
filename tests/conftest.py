import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List

import pytest

from shadowguide.backends.base import Backend
from shadowguide.env import Detected, Environment


class FakeBackend(Backend):
    name = "fake"

    def __init__(self, reply: str = '{"answer":"ok","commands":[]}', local: bool = True):
        self.reply = reply
        self.is_local = local
        self.model = "fake-model"
        self.calls: List[dict] = []

    @property
    def destination(self) -> str:
        return "fake.example"

    def generate(self, system: str, messages: List[Dict[str, str]]) -> str:
        self.calls.append({"system": system, "messages": [dict(m) for m in messages]})
        return self.reply


@pytest.fixture
def env():
    return Environment("linux", "Kali GNU/Linux Rolling", "2024.4", "x86_64", "kali", False,
                       Detected("bash", "medium", "test"), Detected("xterm", "low", "test"), {"nmap": "/usr/bin/nmap"})


class _Handler(BaseHTTPRequestHandler):
    routes = {}
    seen = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        if self.path == "/slow":  # a server that drips its reply one byte at a time
            import time
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            for _ in range(20):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.3)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        _Handler.seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        route = _Handler.routes.get(self.path)
        if route is None:
            self._send(404, {"error": {"message": "nope"}})
            return
        code, payload, hdrs = route
        self._send(code, payload, hdrs)

    do_GET = do_POST = _handle


@pytest.fixture
def server():
    _Handler.routes, _Handler.seen = {}, []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()
