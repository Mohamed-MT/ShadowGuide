"""Static guards for ShadowGuide's core promises. They fail CI if the code drifts.

1. Never executes anything (no subprocess, shell, exec/eval, dynamic import tricks).
2. Never writes to disk (sessions start clean; no history, logs or key storage).
3. Network access exists in exactly one module (backends/http.py).
"""
import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "shadowguide"
FILES = sorted(SRC.rglob("*.py"))

EXEC_MODULES = {"subprocess", "pty", "pexpect", "multiprocessing", "ctypes", "cffi", "runpy", "code", "codeop",
                "webbrowser", "pickle", "marshal", "shelve", "importlib", "imp", "signal", "threading", "sched"}
DISK_MODULES = {"tempfile", "sqlite3", "dbm", "logging", "zipfile", "tarfile", "configparser", "keyring"}
NET_MODULES = {"socket", "ssl", "http", "urllib.request", "urllib.error", "requests", "urllib3", "httpx", "aiohttp",
               "ftplib", "smtplib", "telnetlib", "xmlrpc", "asyncio", "socketserver", "poplib", "imaplib"}
EGRESS_FILE = SRC / "backends" / "http.py"
OS_EXEC_ATTRS = {"system", "popen", "startfile", "posix_spawn", "fork", "kill", "putenv", "unsetenv"}
OS_DISK_ATTRS = {"remove", "unlink", "rename", "renames", "replace", "makedirs", "mkdir", "rmdir", "removedirs",
                 "chmod", "chown", "truncate", "symlink", "link", "write", "open", "utime"}
PATH_WRITE_ATTRS = {"write_text", "write_bytes", "touch", "mkdir", "unlink", "rmdir", "rename", "symlink_to",
                    "hardlink_to", "chmod"}


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:  # skip relative (our own) imports
            yield node.module
            for a in node.names:
                yield node.module + "." + a.name


def _matches(name, banned):
    return any(name == b or name.startswith(b + ".") for b in banned)


def _open_writes(node):
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"):
        return False
    mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")


def _violations(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for name in _imports(tree):
        if _matches(name, EXEC_MODULES):
            found.append("exec-capable import: " + name)
        if _matches(name, DISK_MODULES):
            found.append("disk-capable import: " + name)
        if path != EGRESS_FILE and _matches(name, NET_MODULES):
            found.append("network import outside backends/http.py: " + name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and (node.attr in OS_EXEC_ATTRS or node.attr.startswith(("exec", "spawn", "popen"))):
                found.append("os." + node.attr)
            if node.value.id == "os" and node.attr in OS_DISK_ATTRS:
                found.append("os." + node.attr)
            if node.value.id == "shutil" and node.attr not in {"which", "get_terminal_size"}:
                found.append("shutil." + node.attr)
        if isinstance(node, ast.Attribute) and node.attr in PATH_WRITE_ATTRS and not (
                isinstance(node.value, ast.Name) and node.value.id in {"self", "os"}):
            found.append("write-capable call: ." + node.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"}:
            found.append(node.func.id + "()")
        if _open_writes(node):
            found.append("open() for writing")
    return found


def test_source_files_found():
    assert len(FILES) >= 10


def test_no_execution_no_disk_writes_single_network_egress():
    problems = {str(f.relative_to(SRC)): _violations(f) for f in FILES if _violations(f)}
    assert not problems, problems


def test_egress_module_is_the_only_network_user():
    users = [f for f in FILES if any(_matches(n, {"urllib.request", "ssl"}) for n in _imports(ast.parse(f.read_text())))]
    assert users == [EGRESS_FILE]


def test_guard_actually_detects_violations(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("import subprocess, socket\nimport os\nos.system('x')\nopen('f', 'w')\neval('1')\n")
    found = _violations(bad)
    assert len(found) >= 5
