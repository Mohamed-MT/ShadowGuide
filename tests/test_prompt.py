from shadowguide.prompt import MAX_COMMANDS, build_system_prompt, parse_reply, trim_history


def test_parse_valid_json_with_cautions():
    r = parse_reply('{"answer":"hi","commands":[{"command":"ls","explanation":"list","cautions":"none","prerequisites":["a"],"alternatives":["dir"]}]}')
    c = r.commands[0]
    assert r.structured and c.command == "ls" and c.cautions == ["none"] and c.alternatives == ["dir"]


def test_parse_json_wrapped_in_prose_and_plain_fallback():
    assert parse_reply('Sure! {"answer":"x","commands":[]} thanks').answer == "x"
    r = parse_reply("just words")
    assert not r.structured and r.answer == "just words"


def test_model_text_is_sanitized():
    r = parse_reply('{"answer":"hi\\u001b]52;c;ZXZpbA==\\u0007 there\\u202e","commands":[]}')
    assert r.answer == "hi there"


def test_commands_with_hidden_characters_are_withheld():
    r = parse_reply('{"answer":"a","commands":[{"command":"ls\\u202e -la"},{"command":"pwd"}]}')
    assert [c.command for c in r.commands] == ["pwd"] and r.withheld


def test_command_count_and_length_limits():
    many = ",".join('{"command":"echo %d"}' % i for i in range(20))
    r = parse_reply('{"answer":"a","commands":[%s]}' % many)
    assert len(r.commands) == MAX_COMMANDS and r.withheld
    long = parse_reply('{"answer":"a","commands":[{"command":"echo %s"}]}' % ("x" * 3000))
    assert long.commands == [] and long.withheld


def test_malformed_shapes_do_not_crash():
    for raw in ('{"commands":"rm -rf /"}', '{"commands":[1,null,{"command":5}]}', "[]", '{"answer":5}', ""):
        parse_reply(raw)


def test_history_trim_starts_with_user():
    hist = [{"role": "assistant", "content": "a"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": "b"}]
    assert trim_history(hist, 3)[0]["role"] == "user"


def test_system_prompt_contains_guardrails_and_environment(env):
    prompt = build_system_prompt(env)
    assert "cannot run anything" in prompt and "DATA" in prompt and "Kali" in prompt
