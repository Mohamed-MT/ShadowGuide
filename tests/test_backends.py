import pytest
from conftest import _Handler  # shared in-process test server

from shadowguide.backends import BackendError, Secret, create_backend
from shadowguide.backends.anthropic import AnthropicBackend
from shadowguide.backends.http import MAX_RESPONSE_BYTES, validate_url
from shadowguide.backends.ollama import OllamaBackend
from shadowguide.backends.openai_compat import OpenAICompatBackend


def test_ollama_lists_models_and_picks_one(server):
    _Handler.routes["/api/tags"] = (200, {"models": [{"name": "llama3.2:latest"}, {"name": "qwen:7b"}]}, {})
    b = OllamaBackend(host=server)
    assert "llama3.2:latest" in b.list_models()
    assert "llama3.2:latest" in b.prepare() and b.model == "llama3.2:latest"


def test_ollama_missing_model_is_a_clear_error(server):
    _Handler.routes["/api/tags"] = (200, {"models": [{"name": "qwen:7b"}]}, {})
    with pytest.raises(BackendError, match="ollama pull"):
        OllamaBackend(model="llama3.2", host=server).prepare()


def test_ollama_generate_sends_system_and_json_format(server):
    _Handler.routes["/api/chat"] = (200, {"message": {"content": "{\"answer\":\"hi\"}"}}, {})
    out = OllamaBackend(model="m", host=server).generate("SYS", [{"role": "user", "content": "q"}])
    sent = _Handler.seen[-1]["body"]
    assert out == '{"answer":"hi"}' and sent["messages"][0] == {"role": "system", "content": "SYS"} and sent["format"] == "json"


def test_ollama_rejects_non_loopback():
    for url in ("http://example.com:11434", "http://192.168.1.5:11434", "https://api.openai.com"):
        with pytest.raises(BackendError):
            OllamaBackend(host=url)


def test_openai_compat_sends_bearer_and_parses(server):
    _Handler.routes["/v1/chat/completions"] = (200, {"choices": [{"message": {"content": "hello"}}]}, {})
    b = OpenAICompatBackend("gpt-x", Secret("sk-test-1234567890"), base_url=server + "/v1")
    assert b.is_local and b.generate("SYS", [{"role": "user", "content": "q"}]) == "hello"
    seen = _Handler.seen[-1]
    assert seen["headers"]["authorization"] == "Bearer sk-test-1234567890"
    assert seen["body"]["messages"][0]["role"] == "system"


def test_anthropic_sends_key_header_and_system_field(server):
    _Handler.routes["/v1/messages"] = (200, {"content": [{"type": "text", "text": "hi"}]}, {})
    b = AnthropicBackend("some-model", Secret("sk-ant-test-1234567890"), base_url=server)
    assert b.generate("SYS", [{"role": "user", "content": "q"}]) == "hi"
    seen = _Handler.seen[-1]
    assert seen["headers"]["x-api-key"] == "sk-ant-test-1234567890" and seen["body"]["system"] == "SYS"
    assert all(m["role"] != "system" for m in seen["body"]["messages"])


def test_redirects_are_refused_and_not_followed(server):
    _Handler.routes["/v1/chat/completions"] = (302, b"", {"Location": "http://example.com/steal"})
    b = OpenAICompatBackend("m", Secret("sk-test-1234567890"), base_url=server + "/v1")
    with pytest.raises(BackendError, match="redirect"):
        b.generate("S", [{"role": "user", "content": "q"}])


@pytest.mark.parametrize("code,fragment", [(401, "rejected the API key"), (404, "model name"), (429, "Rate limit")])
def test_http_errors_are_friendly_and_never_leak_the_key(server, code, fragment):
    _Handler.routes["/v1/chat/completions"] = (code, {"error": {"message": "bad sk-test-1234567890 key"}}, {})
    b = OpenAICompatBackend("m", Secret("sk-test-1234567890"), base_url=server + "/v1")
    with pytest.raises(BackendError) as exc:
        b.generate("S", [{"role": "user", "content": "q"}])
    assert fragment in str(exc.value) and "sk-test-1234567890" not in str(exc.value)


def test_provider_error_text_is_sanitized_and_redacted(server):
    _Handler.routes["/v1/chat/completions"] = (400, {"error": {"message": "oops \u001b]52;c;aGk=\u0007 sk-test-1234567890abcd"}}, {})
    b = OpenAICompatBackend("m", Secret("sk-test-1234567890"), base_url=server + "/v1")
    with pytest.raises(BackendError) as exc:
        b.generate("S", [{"role": "user", "content": "q"}])
    assert "\x1b" not in str(exc.value) and "sk-test-1234567890abcd" not in str(exc.value)


def test_oversized_and_invalid_responses_rejected(server):
    _Handler.routes["/api/tags"] = (200, b"x" * (MAX_RESPONSE_BYTES + 10), {})
    with pytest.raises(BackendError, match="larger"):
        OllamaBackend(host=server).list_models()
    _Handler.routes["/api/tags"] = (200, b"not json", {})
    with pytest.raises(BackendError, match="JSON"):
        OllamaBackend(host=server).list_models()
    _Handler.routes["/api/tags"] = (200, b"[1,2]", {})
    with pytest.raises(BackendError):
        OllamaBackend(host=server).list_models()


def test_unreachable_server_message_has_no_url_details():
    with pytest.raises(BackendError) as exc:
        OllamaBackend(host="http://127.0.0.1:1").list_models()
    assert "Could not connect" in str(exc.value)


@pytest.mark.parametrize("url", ["http://api.example.com/v1", "ftp://x.com", "https://user:pw@example.com", "example.com", "https://"])
def test_url_validation_rejects_unsafe_urls(url):
    with pytest.raises(BackendError):
        validate_url(url)


def test_url_validation_allows_https_and_loopback_http():
    assert validate_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"
    assert validate_url("http://localhost:1234/v1") == "http://localhost:1234/v1"


def test_cloud_requires_key_and_model():
    with pytest.raises(BackendError):
        create_backend("openai", None, key=Secret("sk-test-1234567890"))
    with pytest.raises(BackendError):
        OpenAICompatBackend("m", None)
    with pytest.raises(BackendError):
        create_backend("anthropic", "m", key=None)


@pytest.mark.parametrize("bad", ["", "a b", "x;rm -rf /", "../../etc", "m" * 200, "m\nx"])
def test_model_names_validated(bad):
    with pytest.raises(BackendError):
        OllamaBackend(model=bad) if bad else create_backend("openai", bad, key=Secret("sk-test-1234567890"))


def test_secret_never_reveals_itself():
    s = Secret("sk-test-1234567890")
    assert "sk-test" not in repr(s) and "sk-test" not in str(s) and "sk-test" not in "%s %r" % (s, s)
    import pickle
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(BackendError):
        Secret("bad key with spaces")


def test_trailing_newline_is_rejected_by_validators():
    from shadowguide.backends.base import validate_model
    with pytest.raises(BackendError):
        Secret("abcdefgh1234\n")
    with pytest.raises(BackendError):
        validate_model("model\n")


def test_hostile_urls_rejected():
    for url in ("http://127.0.0.1.evil.com/", "http://127.0.0.1@evil.com/", "http://evil.com\\@127.0.0.1/", "http://2130706433/"):
        with pytest.raises(BackendError):
            validate_url(url)
        with pytest.raises(BackendError):
            OllamaBackend(host=url)


def test_request_json_enforces_url_policy_itself():
    from shadowguide.backends.http import request_json
    for url in ("file:///etc/passwd", "ftp://example.com/x", "http://example.com/x", "https://user:pw@example.com", "javascript:alert(1)"):
        with pytest.raises(BackendError):
            request_json(url)


def test_slow_drip_response_hits_the_total_deadline(server):
    import time

    from shadowguide.backends.http import request_json
    start = time.monotonic()
    with pytest.raises(BackendError, match="too long"):
        request_json(server + "/slow", timeout=1.0)
    assert time.monotonic() - start < 4


def test_anthropic_and_openai_unexpected_shapes(server):
    _Handler.routes["/v1/messages"] = (200, {"content": "nope"}, {})
    with pytest.raises(BackendError):
        AnthropicBackend("m", Secret("sk-ant-test-1234567890"), base_url=server).generate("S", [{"role": "user", "content": "q"}])
    _Handler.routes["/v1/messages"] = (200, {"content": [{"type": "text", "text": ""}]}, {})
    with pytest.raises(BackendError):
        AnthropicBackend("m", Secret("sk-ant-test-1234567890"), base_url=server).generate("S", [{"role": "user", "content": "q"}])
    _Handler.routes["/v1/chat/completions"] = (200, {"choices": []}, {})
    b = OpenAICompatBackend("m", Secret("sk-test-1234567890"), base_url=server + "/v1")
    with pytest.raises(BackendError):
        b.generate("S", [{"role": "user", "content": "q"}])
    _Handler.routes["/v1/chat/completions"] = (200, {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}, {})
    assert b.generate("S", [{"role": "user", "content": "q"}]) == "ab"
    _Handler.routes["/v1/chat/completions"] = (200, {"choices": [{"message": {"content": 5}}]}, {})
    with pytest.raises(BackendError):
        b.generate("S", [{"role": "user", "content": "q"}])


def test_ollama_unexpected_reply_and_misc(server):
    _Handler.routes["/api/chat"] = (200, {"message": {"content": 5}}, {})
    with pytest.raises(BackendError):
        OllamaBackend(model="m", host=server).generate("S", [{"role": "user", "content": "q"}])
    _Handler.routes["/api/tags"] = (200, {"models": []}, {})
    with pytest.raises(BackendError, match="no models"):
        OllamaBackend(host=server).prepare()
    assert OllamaBackend(model="m", host=server).describe().startswith("ollama (local)")
    with pytest.raises(BackendError):
        create_backend("bogus", "m")


def test_error_responses_do_not_leak_connections(server):
    import gc
    import warnings

    from shadowguide.backends.http import request_json
    _Handler.routes["/boom"] = (429, {"error": {"message": "slow down"}}, {})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(5):
            with pytest.raises(BackendError):
                request_json(server + "/boom")
        gc.collect()
    assert not [w for w in caught if issubclass(w.category, ResourceWarning)]
