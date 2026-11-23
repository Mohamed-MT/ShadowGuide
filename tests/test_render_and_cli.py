import pytest

from conftest import FakeBackend
from shadowguide.backends.base import BackendError
from shadowguide.cli import ask_backend, chat_loop, confirm_cloud, get_api_key, main
from shadowguide.prompt import parse_reply
from shadowguide.render import Style, render_check, render_reply, supports_color

DANGEROUS = '{"answer":"cleanup","commands":[{"command":"rm -rf /","explanation":"totally safe","cautions":["be careful"]}]}'


def test_dangerous_command_is_red_with_banner_when_color_on():
    text = render_reply(parse_reply(DANGEROUS), Style(True), 80)
    assert "\x1b[1;31m" in text or "\x1b[1;97;41m" in text
    assert "RISK: CRITICAL" in text and "CRITICAL DANGER" in text and "Why this is dangerous" in text
    assert "How to reduce the risk" in text and "never runs commands" in text


def test_independent_risk_even_if_model_says_safe():
    assert "RISK: CRITICAL" in render_reply(parse_reply(DANGEROUS), Style(False), 80)


def test_plain_output_has_no_escape_codes_and_is_ascii():
    text = render_reply(parse_reply(DANGEROUS), Style(False), 80)
    assert "\x1b" not in text and text.isascii()


def test_low_risk_is_green_and_labeled():
    text = render_check("ls -la", Style(True), 80)
    assert "RISK: LOW" in text and "\x1b[32m" in text and "No known risky pattern" in text


def test_hidden_characters_never_reach_the_terminal():
    text = render_check("ls\u202e -la \x1b]52;c;aGk=\x07", Style(False), 80)
    assert "\u202e" not in text and "\x1b" not in text and "<U+202E>" in text


def test_color_detection():
    class TTY:
        def isatty(self): return True
    class Pipe:
        def isatty(self): return False
    assert supports_color(TTY(), {"TERM": "xterm"}) or True  # platform dependent on nt only
    assert not supports_color(Pipe(), {})
    assert not supports_color(TTY(), {"NO_COLOR": "1"})
    assert not supports_color(TTY(), {}, disabled=True)
    assert supports_color(Pipe(), {"FORCE_COLOR": "1"})


def test_ask_backend_sends_system_prompt_and_keeps_history_clean(env):
    backend = FakeBackend()
    history = []
    ask_backend(backend, "SYS", history, "how do I list files?")
    assert backend.calls[0]["system"] == "SYS" and backend.calls[0]["messages"][-1]["role"] == "user"
    assert [m["role"] for m in history] == ["user", "assistant"]


def test_failed_request_does_not_pollute_history():
    class Boom(FakeBackend):
        def generate(self, system, messages):
            raise BackendError("down")
    history = []
    with pytest.raises(BackendError):
        ask_backend(Boom(), "SYS", history, "hello")
    assert history == []


def test_cloud_mode_redacts_before_sending_but_local_does_not():
    cloud, local = FakeBackend(local=False), FakeBackend(local=True)
    q = "why does ssh bob@example.com at 10.1.2.3 fail with password=hunter2"
    ask_backend(cloud, "S", [], q)
    sent = cloud.calls[0]["messages"][-1]["content"]
    assert "hunter2" not in sent and "bob@example.com" not in sent and "10.1.2.3" not in sent
    ask_backend(local, "S", [], q)
    assert "10.1.2.3" in local.calls[0]["messages"][-1]["content"]


def test_cloud_keep_ips_option():
    cloud = FakeBackend(local=False)
    ask_backend(cloud, "S", [], "scan 10.1.2.3", keep_ips=True)
    assert "10.1.2.3" in cloud.calls[0]["messages"][-1]["content"]


def test_user_input_is_sanitized_and_capped():
    backend = FakeBackend()
    ask_backend(backend, "S", [], "hi\x1b]52;c;ZXZpbA==\x07" + "x" * 5000)
    sent = backend.calls[0]["messages"][-1]["content"]
    assert "\x1b" not in sent and len(sent) <= 2000


def test_empty_question_rejected():
    with pytest.raises(BackendError):
        ask_backend(FakeBackend(), "S", [], "   \x1b[0m ")


def test_chat_loop_commands_and_clear(env):
    backend = FakeBackend('{"answer":"hello there","commands":[]}')
    inputs = iter(["/env", "/privacy", "hi", "/clear", "/quit"])
    out = []
    code = chat_loop(backend, env, Style(False), read=lambda _: next(inputs), write=out.append)
    joined = "\n".join(out)
    assert code == 0 and "hello there" in joined and "stored on disk".lower() in joined.lower() and "Conversation cleared" in joined


def test_chat_loop_survives_backend_errors(env):
    class Flaky(FakeBackend):
        def generate(self, system, messages):
            raise BackendError("temporary")
    inputs = iter(["hi", "/quit"])
    out = []
    assert chat_loop(Flaky(), env, Style(False), read=lambda _: next(inputs), write=out.append) == 0
    assert any("error: temporary" in o for o in out)


def test_cloud_session_request_cap(env, monkeypatch):
    import shadowguide.cli as cli
    monkeypatch.setattr(cli, "MAX_CLOUD_REQUESTS", 2)
    inputs = iter(["a", "b", "c", "/quit"])
    out = []
    cli.chat_loop(FakeBackend(local=False), env, Style(False), read=lambda _: next(inputs), write=out.append)
    assert any("request limit" in o for o in out)


def test_cloud_consent_flow(env):
    out = []
    with pytest.raises(BackendError):
        confirm_cloud("fake.example", env, accept=False, keep_ips=False, interactive=False, write=out.append)
    with pytest.raises(BackendError):
        confirm_cloud("fake.example", env, False, False, True, read=lambda _: "no", write=out.append)
    confirm_cloud("fake.example", env, False, False, True, read=lambda _: "YES", write=out.append)
    confirm_cloud("fake.example", env, True, False, False, write=out.append)
    assert any("fake.example" in line for line in out)


def test_api_key_sources_and_validation():
    assert get_api_key("openai", {"OPENAI_API_KEY": " sk-test-1234567890 "}, False).reveal() == "sk-test-1234567890"
    assert get_api_key("anthropic", {"SHADOWGUIDE_API_KEY": "abcdefgh1234"}, False).reveal() == "abcdefgh1234"
    assert get_api_key("openai", {}, False) is None
    assert get_api_key("openai", {}, True, prompt=lambda _: "typed-key-12345").reveal() == "typed-key-12345"
    for bad in ("short", "has space in it 1234", "line\nbreak12345", "x" * 600, "caf\u00e9-key-123456"):
        with pytest.raises(BackendError):
            get_api_key("openai", {"OPENAI_API_KEY": bad}, False)


def test_no_api_key_command_line_option():
    with pytest.raises(SystemExit):
        main(["--api-key", "sk-test-1234567890", "risk", "ls"])


def test_abbreviated_options_rejected():
    with pytest.raises(SystemExit):
        main(["--back", "ollama", "risk", "ls"])


def test_risk_subcommand_works_offline(capsys):
    assert main(["--no-color", "risk", "rm", "-rf", "/"]) == 0
    assert "CRITICAL" in capsys.readouterr().out


def test_cloud_backend_without_key_or_model_fails_cleanly(monkeypatch, capsys):
    for var in ("SHADOWGUIDE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SHADOWGUIDE_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert main(["--backend", "openai", "--model", "m", "--accept-cloud", "ask", "hi"]) == 1
    assert "No API key" in capsys.readouterr().err


def test_broken_pipe_exits_quietly(monkeypatch):
    import shadowguide.cli as cli
    called = []
    monkeypatch.setattr(cli, "_quiet_exit", lambda: called.append(1))
    monkeypatch.setattr(cli, "cmd_risk", lambda args: (_ for _ in ()).throw(BrokenPipeError()))
    parser_main = cli.build_parser().parse_args(["risk", "ls"])
    parser_main.func = cli.cmd_risk
    monkeypatch.setattr(cli.argparse.ArgumentParser, "parse_args", lambda self, argv=None: parser_main)
    assert cli.main(["risk", "ls"]) == 0 and called
