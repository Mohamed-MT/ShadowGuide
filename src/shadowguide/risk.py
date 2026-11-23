"""Independent, deterministic risk classification for commands.

This module never calls a model. A language model can write a dangerous command
and describe it as harmless, so the verdict comes from fixed rules instead.

Limits, stated plainly: this is pattern matching, so a determined person can
write a harmful command that evades it. A LOW result means "no known risky
pattern matched", never "safe". Rules are also applied to a de-obfuscated copy
of the command (quotes, backslashes, backticks and carets removed) to catch
simple tricks like r""m -rf /.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Tuple

from .sanitize import has_confusables, hidden_chars


class Level(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass(frozen=True)
class Finding:
    level: Level
    category: str
    why: str


@dataclass(frozen=True)
class Assessment:
    level: Level
    findings: Tuple[Finding, ...]

    @property
    def dangerous(self) -> bool:
        return self.level >= Level.HIGH


ADVICE: Dict[str, str] = {
    "destructive": "Back up first. Check the exact path or device, and list what will be affected before deleting or writing.",
    "privileged": "Use elevated privileges only when the task needs them, and re-read the command before pressing Enter.",
    "remote-code": "Download the script first, read it, and only then run it. Prefer your OS package manager.",
    "disruptive": "Save your work and make sure nothing important is running. On a remote machine you could lock yourself out.",
    "security-control": "Turn the protection back on as soon as you are done, and avoid this on machines exposed to a network.",
    "system-change": "Note the current setting so you can undo it, and try it on a non-critical machine first if you can.",
    "permissions": "Apply permissions to the narrowest set of files that works, and avoid world-writable modes.",
    "data-loss": "Make sure nothing here is unique or unsaved. Check what will be overwritten or discarded first.",
    "credentials": "Only touch credential stores on systems you own or are authorized to assess, and protect any output.",
    "anti-forensics": "Logs and history may be needed later. Export a copy before clearing anything.",
    "network-scanning": "Get written permission before scanning anything you do not own. Start with one target and gentle settings.",
    "security-tool": "Use only against systems you own or are authorized to test, and start with low-intensity settings.",
    "offensive-tool": "Authorized testing only. Get written permission, define the scope, and test in a lab first.",
    "installs-software": "Install only what you need, from the official source, and check the package name for typos. Prefer built-in tools when they can do the job.",
    "obfuscation": "Hidden or encoded parts cannot be judged by reading the command. Decode it first and be suspicious of its source.",
    "deceptive-text": "Do not run this. It contains characters that make it look different from what the terminal would execute.",
    "multi-line": "Pasting several lines can run each one immediately. Paste into a text editor first, review it, then run it line by line.",
    "reverse-shell": "This opens a remote control channel to another machine. Do not run it unless you are doing authorized testing.",
    "persistence": "This makes something start automatically or grants lasting access. Make sure you can remove it later.",
    "insecure-transport": "Turning off certificate checks removes protection against interception. Fix the certificate problem instead.",
    "account-change": "Accounts decide who can access the machine. Make sure you intend this change and can undo it.",
    "network-capture": "Capture only on networks you own or are authorized to monitor, filter to what you need, and protect or delete capture files.",
}


def advice_for(category: str) -> str:
    return ADVICE.get(category, "Read the command carefully and make sure you understand each part before running it.")


_SEG = r"[^|;&]*"  # stay inside one command segment
_START = r"(?:^|[;&|(`'\"]\s*|\b(?:sudo|doas|env|nohup|command|exec|time|nice|xargs)\s+)"  # command position, incl. wrappers
_END = r"(?=[\s;&|)\"'`]|$)"  # end of an argument: whitespace, separators, closing parens or quotes
_SHELLS = r"(?:ba|z|da|k)?sh\b"

_RULES: List[Tuple[str, Level, str, str]] = [
    # --- destructive
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", Level.CRITICAL, "destructive",
     "Fork bomb: spawns processes until the system becomes unresponsive."),
    (r"\brm\b(?=" + _SEG + r"\s(?:-[a-z]*r[a-z]*|--recursive)\b)(?=" + _SEG + r"\s(?:/+\*?|/(?:home|root|etc|boot|usr|var|bin|sbin|lib|lib64|opt|srv|mnt|media|dev|proc|sys)/*\*?"
     r"|~/?\*?|\$HOME/?\*?|\$\{HOME\}/?\*?)" + _END + r")",
     Level.CRITICAL, "destructive", "Recursive delete aimed at the filesystem root, a top-level system folder, or your home directory."),
    (r"--no-preserve-root", Level.CRITICAL, "destructive", "Disables the safeguard that stops deletion of /."),
    (r"\brm\b" + _SEG + r"\s(?:-[a-z]*r[a-z]*|--recursive)\b", Level.HIGH, "destructive",
     "Recursive delete. Files are removed immediately and do not go to a trash folder."),
    (r"\b(?:rm|del|mv)\b" + _SEG + r"\s(?:/etc|/boot|/bin|/sbin|/usr|/lib)\b", Level.HIGH, "destructive",
     "Removes or moves operating system files, which can leave the system unbootable."),
    (r"\bfind\b" + _SEG + r"(?:-delete\b|-exec\s+rm\b)", Level.HIGH, "destructive",
     "find with delete/exec rm removes everything it matches."),
    (r"\bdd\b" + _SEG + r"\bof=/dev/", Level.CRITICAL, "destructive",
     "Writes raw data to a device and can erase a disk or partition."),
    (r"\bmkfs(?:\.\w+)?\b", Level.CRITICAL, "destructive", "Creates a new filesystem, erasing the target's existing data."),
    (r"\b(?:wipefs|shred|fdisk|sfdisk|parted|diskpart)\b", Level.HIGH, "destructive",
     "Partitioning or wiping tool that can destroy data."),
    (r">\s*/dev/(?:sd|nvme|hd|disk)", Level.CRITICAL, "destructive", "Redirects output onto a disk device."),
    (r"\bcrontab\s+-r\b", Level.HIGH, "destructive", "Deletes all of your scheduled jobs without asking."),
    (r"\bdel\b" + _SEG + r"\s/[sq]\b|\b(?:rd|rmdir)\b" + _SEG + r"\s/s\b|\bRemove-Item\b" + _SEG + r"-Recurse",
     Level.HIGH, "destructive", "Recursive delete. Files are removed immediately."),
    (r"\bformat\s+[a-z]:|\bFormat-Volume\b|\bClear-Disk\b", Level.CRITICAL, "destructive", "Formats or wipes a disk."),
    (r"\bdocker\s+(?:system\s+prune|volume\s+prune|rm\s+-f)", Level.MEDIUM, "data-loss",
     "Deletes containers, images or volumes, including any data stored in them."),
    # --- system changes
    (r">{1,2}\s*/etc/", Level.HIGH, "system-change", "Writes into system configuration under /etc."),
    (r"\breg(?:\.exe)?\s+delete\b|\bbcdedit\b", Level.HIGH, "system-change", "Edits critical Windows registry or boot configuration."),
    (r"\b(?:apt|apt-get|dnf|yum)\s+(?:remove|purge|erase|autoremove)\b", Level.MEDIUM, "system-change",
     "Removes packages and possibly things that depend on them."),
    # --- permissions and privilege
    (r"\bchmod\b" + _SEG + r"\b0?777\b", Level.HIGH, "permissions", "Makes files readable, writable and executable by everyone."),
    (r"\bchmod\b" + _SEG + r"(?:\bu\+s\b|\+s\b|\b[2-7]7[0-7]{2}\b)", Level.HIGH, "permissions",
     "Sets the setuid/setgid bit, so the program runs with its owner's privileges."),
    (r"\b(?:chmod|chown|chgrp)\b" + _SEG + r"\s(?:-[a-z]*r[a-z]*|--recursive)\b", Level.MEDIUM, "permissions",
     "Recursive ownership or permission change can break access across a whole tree."),
    (r"(?<![\w-])(?:sudo|doas|su|pkexec|runas)\b|-Verb\s+RunAs", Level.MEDIUM, "privileged",
     "Runs with elevated privileges, so mistakes can affect the whole system."),
    (r"\bNOPASSWD\b|/etc/sudoers|\bvisudo\b", Level.HIGH, "privileged", "Changes who can run commands as administrator."),
    (r"\bdocker\s+run\b" + _SEG + r"(?:--privileged|-v\s+/:/|--pid=host|--net=host)", Level.HIGH, "privileged",
     "Gives a container broad access to the host machine."),
    (r"\b(?:useradd|adduser)\b|\busermod\b" + _SEG + r"\s-[a-z]*G|\bnet\s+user\b" + _SEG + r"\s/add\b"
     r"|\bnet\s+localgroup\s+administrators\b|\bNew-LocalUser\b", Level.MEDIUM, "account-change",
     "Creates or changes user accounts or administrator membership."),
    # --- remote code, obfuscation
    (r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(?:sudo\s+)?" + _SHELLS,
     Level.HIGH, "remote-code", "Downloads a script and runs it immediately without letting you read it."),
    (r"\b(?:iex|Invoke-Expression)\b", Level.HIGH, "remote-code", "Executes a string as code. Check where the string comes from."),
    (r"\bcertutil\b" + _SEG + r"-urlcache|\bmshta\b|\bregsvr32\b" + _SEG + r"/i:https?:", Level.HIGH, "remote-code",
     "Uses a built-in Windows tool to fetch or run remote content, a common attack technique."),
    (r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?" + _SHELLS, Level.HIGH, "obfuscation",
     "Decodes hidden content and runs it immediately."),
    (r"\b(?:powershell|pwsh)(?:\.exe)?\b" + _SEG + r"\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", Level.HIGH, "obfuscation",
     "Runs an encoded PowerShell command whose real content you cannot read."),
    (r"\$'\\x[0-9a-f]{2}|\$\{IFS\}|\bFromBase64String\b", Level.HIGH, "obfuscation",
     "Uses encoding or escape tricks that hide what the command really does."),
    (r"\beval\b", Level.MEDIUM, "obfuscation", "eval runs a string as code. Check where the string comes from."),
    (r"\\x[0-9a-f]{2}|\$\(\s*(?:echo|printf|base64|xxd|rev)\b", Level.MEDIUM, "obfuscation",
     "Builds part of the command from escapes or other commands, so it cannot be judged by reading it."),
    (r"(?:^|[;&|(]\s*)(?:\$\{?\w+\}?)+(?:\s|$)", Level.MEDIUM, "obfuscation",
     "The command name comes from a variable, so what really runs is hidden."),
    (r"/dev/tcp/|\b(?:nc|ncat|netcat)\b" + _SEG + r"\s-[a-z]*e\b|\bbash\s+-i\b" + _SEG + r">&|\bsocat\b" + _SEG + r"\bexec:"
     r"|\bmkfifo\b" + _SEG + r"\bn(?:c|cat)\b", Level.CRITICAL, "reverse-shell",
     "Matches the pattern of a reverse shell, which hands control of this machine to a remote host."),
    # --- persistence
    (r"\bschtasks\b" + _SEG + r"\s/create\b|\b(?:Register-ScheduledTask|New-Service)\b|\bsystemctl\s+enable\b"
     r"|\blaunchctl\s+(?:load|bootstrap)\b", Level.MEDIUM, "persistence", "Makes something start automatically."),
    (r"\\CurrentVersion\\Run\b|>{1,2}\s*\S*authorized_keys", Level.HIGH, "persistence",
     "Adds a startup entry or a login key, giving lasting access."),
    (r">{1,2}\s*\S*\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b", Level.MEDIUM, "persistence",
     "Modifies a shell startup file, so the change runs every time you open a terminal."),
    # --- disruption
    (r"(?<!man\s)(?<!which\s)(?<!echo\s)(?<!grep\s)\b(?:shutdown|reboot|poweroff)\b|" + _START + r"halt\b"
     r"|\bsystemctl\s+(?:halt|kexec)\b|\binit\s+[06]\b|\b(?:Stop|Restart)-Computer\b",
     Level.HIGH, "disruptive", "Shuts down or restarts the machine and interrupts anything running."),
    (r"\bkill\b" + _SEG + r"\s-(?:9|KILL)\b|\b(?:killall|pkill)\b|\btaskkill\b" + _SEG + r"\s/f\b|\bStop-Process\b" + _SEG + r"-Force",
     Level.MEDIUM, "disruptive", "Force-kills processes, which can lose unsaved data or break services."),
    (r"\bsystemctl\s+(?:stop|disable|mask)\b|\b(?:Stop|Disable)-Service\b|\bsc(?:\.exe)?\s+(?:stop|delete)\b",
     Level.MEDIUM, "disruptive", "Stops or disables a service that other things may depend on."),
    (r"\bip\s+link\s+set\b" + _SEG + r"\bdown\b|\bifconfig\s+\S+\s+down\b|\bDisable-NetAdapter\b"
     r"|\bnetsh\b" + _SEG + r"\bdisable\b|\bnmcli\b" + _SEG + r"\b(?:down|disconnect)\b", Level.MEDIUM, "disruptive",
     "Turns off a network connection. On a remote machine this can cut you off."),
    # --- security controls
    (r"\biptables\b" + _SEG + r"\s-F\b|\bufw\s+(?:disable|reset)\b|\bnft\s+flush\s+ruleset\b"
     r"|\bnetsh\b" + _SEG + r"advfirewall" + _SEG + r"\boff\b|Set-NetFirewallProfile" + _SEG + r"-Enabled\s+False",
     Level.HIGH, "security-control", "Disables or flushes the firewall and exposes the machine."),
    (r"\bsetenforce\s+0\b|Set-MpPreference" + _SEG + r"-DisableRealtimeMonitoring\s+\$?true",
     Level.HIGH, "security-control", "Turns off a host security protection (SELinux or Defender)."),
    (r"\bSet-ExecutionPolicy\b" + _SEG + r"\b(?:Bypass|Unrestricted)\b", Level.HIGH, "security-control",
     "Removes PowerShell's script-running safeguards."),
    (r"-ExecutionPolicy\s+Bypass\b", Level.MEDIUM, "security-control", "Runs PowerShell while ignoring its script-running safeguards."),
    (r"\bcurl\b" + _SEG + r"\s(?:-k|--insecure)\b|\bwget\b" + _SEG + r"--no-check-certificate|-SkipCertificateCheck",
     Level.MEDIUM, "insecure-transport", "Turns off TLS certificate checks, which allows interception."),
    # --- data and credentials
    (r"\bgit\b" + _SEG + r"\bpush\b" + _SEG + r"(?:--force\b|\s-f\b)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*f",
     Level.MEDIUM, "data-loss", "Can overwrite remote history or discard local work permanently."),
    (r"/etc/shadow\b|\b(?:mimikatz|lsass)\b", Level.HIGH, "credentials",
     "Touches credential stores. Only do this on systems you own or are authorized to assess."),
    (r"\bhistory\s+-c\b|\bwevtutil\s+cl\b|\bClear-EventLog\b", Level.HIGH, "anti-forensics",
     "Erases history or logs that may be needed for troubleshooting or investigation."),
    # --- installs
    (r"\b(?:pip3?|pipx|gem|cargo|go|snap|brew|choco|winget|scoop)\s+install\b|\bpython3?\s+-m\s+pip\s+install\b"
     r"|\bnpm\s+(?:install|i|add)\b|\b(?:apt|apt-get|dnf|yum|zypper)\s+(?:-y\s+)?install\b|\bpacman\s+-S\b"
     r"|\b(?:Install-Module|Install-Package|Install-Script)\b",
     Level.MEDIUM, "installs-software", "Installs software onto this machine."),
    # --- backups, disks and platform-specific destruction
    (r"\bvssadmin\b" + _SEG + r"\bdelete\b|\bwmic\b" + _SEG + r"\bshadowcopy\b" + _SEG + r"\bdelete\b|\bwbadmin\b" + _SEG + r"\bdelete\b"
     r"|\btmutil\s+delete\b", Level.CRITICAL, "destructive",
     "Deletes backups or restore points, a classic step in ransomware attacks."),
    (r"\b(?:rd|rmdir|del|erase|ri|Remove-Item)\b" + _SEG + r"\s\"?[a-z]:\\?(?:\*|Windows(?:\\System32)?\\?)?" + _END,
     Level.CRITICAL, "destructive", "Deletes a whole drive or the Windows folder."),
    (r"\b(?:ri|erase)\b" + _SEG + r"\s-(?:r|recurse)\b", Level.HIGH, "destructive", "Recursive delete. Files are removed immediately."),
    (r"\bdiskutil\s+(?:erase\w*|secureErase|partitionDisk|zeroDisk|apfs\s+deleteContainer)\b", Level.CRITICAL, "destructive",
     "Erases or repartitions a disk."),
    (r"\b(?:cp|mv|tee)\b" + _SEG + r"\s/dev/(?:sd|nvme|hd|disk|mmcblk|vd|xvd)\w*", Level.CRITICAL, "destructive",
     "Writes onto a disk device."),
    (r"\b(?:blkdiscard|mkswap|lvremove|vgremove|pvremove|lvreduce)\b|\bzpool\s+destroy\b|\bzfs\s+destroy\b"
     r"|\bcryptsetup\s+(?:luksFormat|erase)\b|\bhdparm\b" + _SEG + r"--security-erase|\bnvme\s+format\b|\bcipher\s+/w\b"
     r"|\buserdel\b" + _SEG + r"\s-[a-z]*r", Level.HIGH, "destructive",
     "Erases or reformats storage, or deletes an account together with its files."),
    (r"sysrq-trigger", Level.CRITICAL, "disruptive", "Triggers low-level kernel actions such as an immediate crash or reboot."),
    (r"\b(?:chmod|chown|chgrp)\b" + _SEG + r"\s(?:-[a-z]*r[a-z]*|--recursive)\b" + _SEG + r"\s/+" + _END, Level.CRITICAL, "permissions",
     "A recursive permission or ownership change on the filesystem root can break the entire system."),
    (r"\bicacls\b" + _SEG + r"(?:Everyone|\*S-1-1-0)" + _SEG + r"\(?F\)?|\btakeown\b" + _SEG + r"/r\b", Level.HIGH, "permissions",
     "Gives everyone full control, or takes ownership of a whole folder tree."),
    (r"\bAdd-MpPreference\b" + _SEG + r"-Exclusion|\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b"
     r"|\breg\b" + _SEG + r"\badd\b" + _SEG + r"Disable(?:AntiSpyware|AntiVirus|RealtimeMonitoring)", Level.HIGH, "security-control",
     "Weakens malware or system-integrity protection."),
    (r"\biptables\b" + _SEG + r"\s-P\s+\w+\s+(?:DROP|REJECT)\b", Level.HIGH, "disruptive",
     "Sets a default-deny firewall policy, which can lock you out of a remote machine."),
    (r"(?<![/\w.-])(?:chpasswd|passwd)\b|\buserdel\b", Level.MEDIUM, "account-change",
     "Changes or removes user accounts or passwords."),
    (r"\bsysctl\s+-w\b|\bmount\b" + _SEG + r"remount|\bumount\b" + _SEG + r"\s-[a-z]*[fl]\b|\bswapoff\s+-a\b|\bnet\s+stop\b"
     r"|\blaunchctl\s+unload\b", Level.MEDIUM, "system-change",
     "Changes kernel settings, mounts or services in a way that can disrupt the system."),
    # --- traffic capture and scanners
    (r"\b(?:tcpdump|tshark|dumpcap|wireshark)\b", Level.MEDIUM, "network-capture",
     "Captures network traffic, which can contain passwords and personal data."),
    (r"\bnmap\b" + _SEG + r"--script[=\s]+\S*(?:exploit|brute|dos|intrusive|vuln|fuzzer|malware)", Level.HIGH, "offensive-tool",
     "Runs intrusive or exploit scripts against targets."),
    (r"\b(?:burpsuite|nessuscli|openvas|gvm-cli|zaproxy)\b|\bzap\.sh\b", Level.MEDIUM, "security-tool",
     "Vulnerability scanner or web proxy that sends intrusive traffic. Use only with authorization."),
    # --- security tools
    (r"\b(?:nmap|masscan|zmap|unicornscan)\b", Level.MEDIUM, "network-scanning",
     "Actively probes hosts. Scan only systems you own or have written permission to test."),
    (r"\b(?:gobuster|ffuf|dirb|dirbuster|wfuzz|nikto|feroxbuster|hashcat|john)\b", Level.MEDIUM, "security-tool",
     "Generates heavy or intrusive traffic, or cracks hashes. Use only with authorization."),
    (r"\b(?:hydra|medusa|sqlmap|msfconsole|msfvenom|responder|ettercap|bettercap|aircrack-ng)\b", Level.HIGH, "offensive-tool",
     "Offensive security tool that can break into or disrupt systems. Authorized testing only."),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.MULTILINE), lvl, cat, why) for p, lvl, cat, why in _RULES]
_SQUASH = re.compile(r"[\\'\"`^]")
MAX_SANE_LENGTH = 1000


def classify(command: str) -> Assessment:
    findings: List[Finding] = []
    seen = set()

    def add(level: Level, category: str, why: str) -> None:
        if (category, why) not in seen:
            seen.add((category, why))
            findings.append(Finding(level, category, why))

    squashed = _SQUASH.sub("", command)
    variants = [command] if squashed == command else [command, squashed]
    for pattern, level, category, why in _COMPILED:
        if any(pattern.search(v) for v in variants):
            add(level, category, why)

    hidden = hidden_chars(command)
    if hidden:
        add(Level.CRITICAL, "deceptive-text",
            "Contains invisible, control or direction-changing characters ({}).".format("; ".join(hidden[:3])))
    elif has_confusables(command):
        add(Level.MEDIUM, "deceptive-text",
            "Contains look-alike letters from another alphabet, which can disguise a different command.")
    if len([line for line in command.split("\n") if line.strip()]) > 1:
        add(Level.MEDIUM, "multi-line", "Spans several lines, so pasting it into a terminal may run lines immediately.")
    if len(command) > MAX_SANE_LENGTH:
        add(Level.MEDIUM, "obfuscation", "Unusually long for a single command, which makes it hard to review.")

    # Within one category keep only the most severe findings, so the display is not repetitive.
    top_by_category: Dict[str, Level] = {}
    for f in findings:
        top_by_category[f.category] = max(top_by_category.get(f.category, Level.LOW), f.level)
    findings = [f for f in findings if f.level == top_by_category[f.category]]
    findings.sort(key=lambda f: f.level, reverse=True)
    return Assessment(findings[0].level if findings else Level.LOW, tuple(findings))
