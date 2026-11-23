"""Property-based fuzzing: whatever the input, the safety invariants must hold."""
import contextlib
import json
import os
import re

from conftest import FakeBackend
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shadowguide.backends.base import BackendError
from shadowguide.backends.http import validate_url
from shadowguide.cli import ask_backend
from shadowguide.env import detect_shell, detect_terminal
from shadowguide.prompt import MAX_COMMAND_CHARS, MAX_COMMANDS, parse_reply
from shadowguide.render import Style, render_check, render_reply
from shadowguide.risk import Level, classify
from shadowguide.sanitize import escape_for_display, hidden_chars, limit_input, redact, strip_unsafe

FUZZ = settings(max_examples=int(os.environ.get("SHADOWGUIDE_FUZZ_EXAMPLES", "200")), deadline=None, suppress_health_check=[HealthCheck.too_slow])

ANY_TEXT = st.text(alphabet=st.characters(exclude_categories=()), max_size=300)  # includes lone surrogates
TRICKY = st.lists(st.sampled_from(["\x1b", "]", "[", "\x07", "\u202e", "\u200b", "\r", "\n", " ", "a", "5", "2", ";", "m", "\\",
                                   "\x9b", "\u00a0", "\U000e0041", "\ufe0f", "'", '"', "$", "(", ")", "|", "&", "rm -rf /"]),
                  max_size=60).map("".join)
TEXT = ANY_TEXT | TRICKY
JSON_KEYS = st.sampled_from(["answer", "commands", "command", "explanation", "cautions", "prerequisites", "alternatives", "notes"])
JSON_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers() | TEXT.filter(lambda s: not any(0xD800 <= ord(c) <= 0xDFFF for c in s)),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(JSON_KEYS, children, max_size=6),
    max_leaves=25)
STYLE_CODES = re.compile(r"\x1b\[[0-9;]*m")


@FUZZ
@given(TEXT)
def test_strip_unsafe_is_clean_and_idempotent(text):
    out = strip_unsafe(text)
    assert "\x1b" not in out and hidden_chars(out) == []
    assert strip_unsafe(out) == out


@FUZZ
@given(TEXT)
def test_escape_for_display_is_clean(text):
    out = escape_for_display(text)
    assert "\x1b" not in out and hidden_chars(out) == []


@FUZZ
@given(TEXT)
def test_limit_input_bounds_and_cleans(text):
    out, _ = limit_input(text)
    assert len(out) <= 2000 and "\x1b" not in out and hidden_chars(out) == []


@FUZZ
@given(TEXT)
def test_classify_never_crashes_and_is_deterministic(text):
    a, b = classify(text), classify(text)
    assert a == b and a.level in Level
    if hidden_chars(text):
        assert a.level == Level.CRITICAL


@FUZZ
@given(TEXT)
def test_parse_reply_on_arbitrary_text_is_safe(text):
    reply = parse_reply(text)
    assert "\x1b" not in reply.answer and hidden_chars(reply.answer) == []


@FUZZ
@given(JSON_VALUE)
def test_parse_reply_on_arbitrary_json_enforces_limits(value):
    reply = parse_reply(json.dumps(value))
    assert len(reply.commands) <= MAX_COMMANDS
    for c in reply.commands:
        assert len(c.command) <= MAX_COMMAND_CHARS and hidden_chars(c.command) == []
        for field in (c.explanation, *c.cautions, *c.prerequisites, *c.alternatives):
            assert hidden_chars(field) == []


@FUZZ
@given(st.one_of(TEXT, JSON_VALUE.map(json.dumps)))
def test_rendered_output_can_never_carry_terminal_control_or_hidden_text(raw):
    reply = parse_reply(raw)
    plain = render_reply(reply, Style(False), 80)
    assert "\x1b" not in plain and hidden_chars(plain) == []
    colored = render_reply(reply, Style(True), 80)
    assert "\x1b" not in STYLE_CODES.sub("", colored)  # only ShadowGuide's own color codes
    assert hidden_chars(colored.replace("\x1b", "")) == []


@FUZZ
@given(TEXT)
def test_render_check_is_safe_for_any_command(command):
    out = render_check(command, Style(False), 80)
    assert "\x1b" not in out and hidden_chars(out) == []


SECRET_BODY = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=24, max_size=48)


@FUZZ
@given(SECRET_BODY, st.sampled_from(["sk-", "sk-ant-api03-", "ghp_", "xoxb-"]), TEXT)
def test_planted_secrets_never_survive_redaction(body, prefix, noise):
    secret = prefix + body
    out, count = redact("{} {} {}".format(noise, secret, noise))
    assert secret not in out and count >= 1


@FUZZ
@given(TEXT)
def test_redact_never_crashes(text):
    out, count = redact(text)
    assert isinstance(out, str) and count >= 0


@FUZZ
@given(ANY_TEXT)
def test_validate_url_only_raises_backend_errors(url):
    with contextlib.suppress(BackendError):
        validate_url(url)


@FUZZ
@given(st.dictionaries(st.text(max_size=12), st.text(max_size=60), max_size=8), st.sampled_from(["windows", "linux", "macos", "other"]))
def test_detection_never_crashes(env, family):
    assert detect_shell(env, family).value
    assert detect_terminal(env).value


@FUZZ
@given(st.one_of(TEXT, JSON_VALUE.map(json.dumps)), TEXT)
def test_full_pipeline_with_hostile_model_and_user(reply_text, user_text):
    backend = FakeBackend(reply=reply_text, local=False)
    history = []
    try:
        reply, _, _ = ask_backend(backend, "SYS", history, user_text)
    except BackendError:
        return  # only acceptable failure: an empty question
    sent = backend.calls[0]["messages"][-1]["content"]
    assert "\x1b" not in sent and hidden_chars(sent) == [] and len(sent) <= 2000
    out = render_reply(reply, Style(False), 80)
    assert "\x1b" not in out and hidden_chars(out) == []
    assert all(hidden_chars(m["content"]) == [] for m in history)
