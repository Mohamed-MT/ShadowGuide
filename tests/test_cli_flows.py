import io
import json
import runpy
import sys
import types

import pytest
from conftest import _Handler

import shadowguide.cli as cli
from shadowguide.render import Style, command_block, supports_color
from shadowguide.risk import classify

REPLY = {"answer": "Here you go", "commands": [
    {"command": "rm -rf ~/old", "explanation": "Deletes old.", "cautions": ["No undo."],
     "prerequisites": ["Back it up"], "alternatives": ["trash-put ~/old", "rm -rf /"]}]}


def _ollama(server):
    _Handler.routes["/api/tags"] = (200, {"models": [{"name": "m:latest"}]}, {})
    _Handler.routes["/api/chat"] = (200, {"message": {"content": json.dumps(REPLY)}}, {})


def test_ask_end_to_end_with_local_backend(server, capsys):
    _ollama(server)
    assert cli.main(["--host", server, "--no-color", "ask", "clean", "up"]) == 0
    out = capsys.readouterr().out
    assert "Using the Ollama model 'm:latest'" in out and "RISK: HIGH" in out
    assert "Why this is dangerous" in out and "[risk: CRITICAL]" in out  # alternative rated independently


def test_unreachable_ollama_is_a_clean_error(capsys):
    assert cli.main(["--host", "http://127.0.0.1:1", "ask", "hi"]) == 1
    assert "Could not connect" in capsys.readouterr().err


def test_doctor_runs_and_masks_home(server, capsys):
    _ollama(server)
    assert cli.main(["--host", server, "doctor"]) == 0
    out = capsys.readouterr().out
    assert "environment report" in out and "Ollama is running" in out


def test_doctor_for_cloud_backend_makes_no_request(capsys):
    assert cli.main(["--backend", "openai", "doctor"]) == 0
    assert "not contacted" in capsys.readouterr().out


def test_mask_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/alice")
    monkeypatch.setenv("USERPROFILE", "/home/alice")
    assert cli._mask_home("/home/alice/bin/nmap").startswith("~") and "alice" not in cli._mask_home("/home/alice/bin/nmap")
    assert cli._mask_home("/usr/bin/nmap") == "/usr/bin/nmap"


def test_chat_wiring(server, monkeypatch):
    _ollama(server)
    seen = {}
    monkeypatch.setattr(cli, "chat_loop", lambda backend, env, style, keep_ips: seen.setdefault("backend", backend) and 0)
    assert cli.main(["--host", server]) == 0 and seen["backend"].model == "m:latest"


def test_openai_compatible_local_endpoint_needs_no_key(server, capsys, monkeypatch):
    for var in ("SHADOWGUIDE_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    _Handler.routes["/v1/chat/completions"] = (200, {"choices": [{"message": {"content": json.dumps(REPLY)}}]}, {})
    assert cli.main(["--backend", "openai", "--model", "m", "--base-url", server + "/v1", "--no-color", "ask", "hi"]) == 0
    assert "RISK: HIGH" in capsys.readouterr().out


def test_consent_is_requested_before_the_key_and_before_any_request(monkeypatch, capsys):
    for var in ("SHADOWGUIDE_API_KEY", "OPENAI_API_KEY", "SHADOWGUIDE_MODEL"):
        monkeypatch.delenv(var, raising=False)
    prompted = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_: prompted.append(1) or "sk-test-1234567890")
    assert cli.main(["--backend", "openai", "--model", "m", "ask", "hi"]) == 1  # stdin is not a tty under pytest
    assert "needs your confirmation" in capsys.readouterr().err and not prompted
    assert cli.main(["--backend", "openai", "--model", "m", "--accept-cloud", "ask", "hi"]) == 1
    assert "No API key found" in capsys.readouterr().err


def test_cloud_backend_requires_model_before_anything_else(monkeypatch, capsys):
    monkeypatch.delenv("SHADOWGUIDE_MODEL", raising=False)
    assert cli.main(["--backend", "anthropic", "ask", "hi"]) == 1
    assert "model name" in capsys.readouterr().err


def test_invalid_shell_override_is_rejected(capsys):
    assert cli.main(["--shell", "bash;rm -rf /", "doctor"]) == 1
    assert "--shell must be a short name" in capsys.readouterr().err


def test_unexpected_errors_never_leak_details(monkeypatch, capsys):
    def boom(args):
        raise RuntimeError("sk-secret-1234567890 /home/alice")
    monkeypatch.setattr(cli, "cmd_privacy", boom)
    assert cli.main(["privacy"]) == 70
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "sk-secret" not in err and "alice" not in err
    monkeypatch.setenv("SHADOWGUIDE_DEBUG", "1")
    with pytest.raises(RuntimeError):
        cli.main(["privacy"])


def test_keyboard_interrupt_exits_130(monkeypatch):
    monkeypatch.setattr(cli, "cmd_privacy", lambda args: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["privacy"]) == 130


def test_module_entry_point(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["shadowguide", "privacy"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("shadowguide", run_name="__main__")
    assert exc.value.code == 0 and "Stored on disk" in capsys.readouterr().out


def test_unencodable_output_does_not_crash(monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    assert cli.main(["--no-color", "risk", "echo", "caf\u00e9", "\u2603"]) == 0


def test_risk_with_no_command_is_a_usage_error(capsys):
    assert cli.main(["risk"]) == 2


def test_api_key_prompt_empty_input_returns_none():
    assert cli.get_api_key("openai", {}, True, prompt=lambda _: "   ") is None


def test_supports_color_windows_branches():
    class TTY:
        def isatty(self):
            return True
    import shadowguide.render as render
    fake_os = types.SimpleNamespace(name="nt")
    original = render.os
    render.os = fake_os
    try:
        assert not supports_color(TTY(), {})
        assert supports_color(TTY(), {"WT_SESSION": "x"})
    finally:
        render.os = original
    assert supports_color(TTY(), {"FORCE_COLOR": "1"}) and not supports_color(TTY(), {"FORCE_COLOR": "0", "TERM": "dumb"})


def test_command_block_renders_every_section():
    lines = command_block("COMMAND 1 of 1", "ls", classify("ls"), Style(False), 80, "lists", ["careful"], ["need ls"], ["dir", "rm -rf /"])
    text = "\n".join(lines)
    for fragment in ("What it does", "Also keep in mind", "Before you run it", "Alternatives", "[risk: CRITICAL]"):
        assert fragment in text
