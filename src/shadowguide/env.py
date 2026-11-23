"""Environment detection.

Everything here is read-only and in-process: platform introspection, environment
variables, a read of /etc/os-release, and PATH lookups through shutil.which.
No subprocesses are used anywhere in ShadowGuide.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Tuple

TOOL_GROUPS: Dict[str, Tuple[str, ...]] = {
    "common": ("curl", "wget", "ssh", "scp", "git", "python3", "python", "openssl", "tar", "grep", "awk", "sed"),
    "network": ("ping", "traceroute", "tracert", "nslookup", "dig", "ip", "ifconfig", "ss", "netstat",
                "nmap", "tshark", "wireshark", "tcpdump", "nc", "ncat"),
    "security": ("gobuster", "ffuf", "nikto", "sqlmap", "hydra", "john", "hashcat", "msfconsole",
                 "burpsuite", "nessuscli", "lynis", "clamscan"),
    "windows": ("powershell", "pwsh", "cmd", "netsh", "ipconfig", "wsl", "winget", "choco", "sc",
                "tasklist", "taskkill", "reg", "certutil"),
    "macos": ("brew", "networksetup", "launchctl", "defaults", "diskutil", "pfctl"),
    "linux": ("apt", "dnf", "yum", "pacman", "zypper", "systemctl", "journalctl", "ufw", "iptables", "nft"),
}


@dataclass(frozen=True)
class Detected:
    value: str
    confidence: str  # "high" | "medium" | "low"
    source: str


@dataclass
class Environment:
    os_family: str  # "windows" | "macos" | "linux" | "other"
    os_name: str
    os_version: str
    arch: str
    distro_id: Optional[str]
    wsl: bool
    shell: Detected
    terminal: Detected
    tools: Dict[str, str]  # tool name -> path

    def prompt_summary(self) -> str:
        """Compact description for the model. Tool names only, never paths."""
        lines = [
            "Operating system: {} {} ({}){}".format(
                _clean(self.os_name), _clean(self.os_version), _clean(self.arch),
                ", running under WSL" if self.wsl else "",
            )
        ]
        if self.distro_id:
            lines.append("Distribution ID: " + _clean(self.distro_id))
        lines.append("Shell: {} (detection confidence: {})".format(_clean(self.shell.value), self.shell.confidence))
        lines.append("Terminal: " + _clean(self.terminal.value))
        names = ", ".join(sorted(self.tools)) or "none detected"
        lines.append("Notable tools found on PATH: " + names)
        return "\n".join(lines)


def _clean(value: str) -> str:
    return " ".join(str(value).split())[:120]


def parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"').strip("'")
    return out


def read_os_release(paths: Tuple[str, ...] = ("/etc/os-release", "/usr/lib/os-release")) -> Dict[str, str]:
    for path in paths:
        try:
            return parse_os_release(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return {}


def _windows_name(version: str) -> str:
    try:
        build = int(version.split(".")[-1])
    except ValueError:
        return "Windows"
    return "Windows 11" if build >= 22000 else "Windows 10"


def detect_os() -> Tuple[str, str, str, Optional[str], bool]:
    """Return (family, name, version, distro_id, wsl)."""
    system = platform.system()
    if system == "Windows":
        version = platform.win32_ver()[1] or platform.version()
        return "windows", _windows_name(version), version, None, False
    if system == "Darwin":
        return "macos", "macOS", platform.mac_ver()[0] or platform.release(), None, False
    if system == "Linux":
        info = read_os_release()
        wsl = "microsoft" in platform.release().lower()
        name = info.get("PRETTY_NAME") or "Linux"
        version = info.get("VERSION_ID") or platform.release()
        return "linux", name, version, info.get("ID"), wsl
    return "other", system or "unknown", platform.release(), None, False


_SHELL_NAME_RE = re.compile(r"[a-z0-9._+\-]{1,32}")


def detect_shell(env: Mapping[str, str], os_family: str, override: Optional[str] = None) -> Detected:
    if override:
        name = override.strip().lower()
        if not _SHELL_NAME_RE.fullmatch(name):
            raise ValueError("--shell must be a short name such as bash, zsh, powershell or cmd.")
        return Detected(name, "high", "user override")
    shell_var = env.get("SHELL")
    if os_family == "windows":
        if shell_var:  # Git Bash, MSYS2, Cygwin
            return Detected(os.path.basename(shell_var).lower().replace(".exe", ""), "medium", "$SHELL (MSYS/Cygwin style)")
        if env.get("PROMPT"):
            return Detected("cmd", "medium", "PROMPT variable is set (cmd.exe sets it for child processes)")
        if env.get("PSModulePath"):
            return Detected("powershell", "low", "PSModulePath present; cmd.exe is not ruled out")
        return Detected("unknown", "low", "no shell indicators found")
    if shell_var:
        return Detected(os.path.basename(shell_var), "medium", "$SHELL is the login shell and may differ from the current one")
    return Detected("unknown", "low", "no shell indicators found")


def detect_terminal(env: Mapping[str, str]) -> Detected:
    if env.get("WT_SESSION"):
        return Detected("Windows Terminal", "high", "WT_SESSION")
    program = env.get("TERM_PROGRAM")
    if program:
        version = env.get("TERM_PROGRAM_VERSION")
        return Detected(program + (" " + version if version else ""), "high", "TERM_PROGRAM")
    if env.get("KONSOLE_VERSION"):
        return Detected("Konsole", "high", "KONSOLE_VERSION")
    if env.get("VTE_VERSION") or env.get("GNOME_TERMINAL_SCREEN"):
        return Detected("VTE-based terminal (e.g. GNOME Terminal)", "medium", "VTE_VERSION")
    if env.get("TMUX"):
        return Detected("tmux", "medium", "TMUX")
    term = env.get("TERM")
    if term:
        return Detected(term, "low", "TERM")
    return Detected("unknown", "low", "no terminal indicators found")


def detect_tools(os_family: str, which: Callable[[str], Optional[str]] = shutil.which) -> Dict[str, str]:
    groups = ["common", "network", "security"]
    if os_family in TOOL_GROUPS:
        groups.append(os_family)
    found: Dict[str, str] = {}
    for group in groups:
        for name in TOOL_GROUPS[group]:
            path = which(name)
            if path:
                found[name] = path
    return found


def detect_environment(
    env: Optional[Mapping[str, str]] = None,
    shell_override: Optional[str] = None,
    probe_tools: bool = True,
) -> Environment:
    env = os.environ if env is None else env
    family, name, version, distro_id, wsl = detect_os()
    shell = detect_shell(env, family, shell_override)
    return Environment(
        family, name, version, platform.machine() or "unknown", distro_id, wsl,
        shell, detect_terminal(env), detect_tools(family) if probe_tools else {},
    )
