"""Text hygiene.

Two jobs:
1. Neutralize anything that could abuse a terminal or deceive a reader: ANSI/OSC
   escape sequences (including OSC 52 clipboard writes), control characters,
   bidirectional overrides, zero-width and "tag" characters, and look-alike scripts.
2. Redact sensitive values before text leaves the machine (cloud mode only).

Model output and anything the user pastes is treated as untrusted data.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Pattern, Tuple

MAX_INPUT_CHARS = 2000

_ESCAPES = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"        # OSC: titles, hyperlinks, clipboard (OSC 52)
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"            # DCS, SOS, PM, APC strings
    r"|\x1b\[[0-?]*[ -/]*[@-~]"                  # CSI: cursor movement, colors, erase
    r"|\x1b[@-_]"                                 # other two-byte escapes
    r"|\x9b[0-?]*[ -/]*[@-~]"                    # 8-bit CSI
    r"|\x1b"                                      # stray ESC
)

_HIDDEN_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"))
_BLANK_LOOKING = frozenset("\u3164\u115f\u1160\u2800\u034f\u180e")
_SPOOF_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "FULLWIDTH", "MATHEMATICAL")


def _is_variation_selector(ch: str) -> bool:
    o = ord(ch)
    return 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF


def _is_hidden(ch: str) -> bool:
    if ch in ("\n", "\t"):
        return False
    return unicodedata.category(ch) in _HIDDEN_CATEGORIES or ch in _BLANK_LOOKING or _is_variation_selector(ch)


def _is_odd_space(ch: str) -> bool:
    return ch != " " and unicodedata.category(ch) == "Zs"


def strip_unsafe(text: str) -> str:
    """Remove escape sequences and invisible/control characters. Keeps \\n and \\t."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ESCAPES.sub("", text)
    out: List[str] = []
    for ch in text:
        if ch == " " or ch in ("\n", "\t"):
            out.append(ch)
        elif _is_odd_space(ch):
            out.append(" ")
        elif not _is_hidden(ch):
            out.append(ch)
    return "".join(out)


def hidden_chars(text: str) -> List[str]:
    """Describe invisible, control or unusual-space characters found in text."""
    seen: Dict[str, str] = {}
    for ch in text:
        if _is_hidden(ch) or _is_odd_space(ch):
            seen.setdefault(ch, "U+{:04X} {}".format(ord(ch), unicodedata.name(ch, "control character")))
    return list(seen.values())


def has_confusables(text: str) -> bool:
    """True if text contains letters from scripts commonly used to spoof ASCII."""
    return any(ord(ch) > 127 and unicodedata.name(ch, "").startswith(_SPOOF_SCRIPTS) for ch in text)


def escape_for_display(text: str) -> str:
    """Show hidden characters as <U+XXXX> so they can never act on the terminal."""
    out: List[str] = []
    for ch in text:
        if ch in (" ", "\n", "\t") or not (_is_hidden(ch) or _is_odd_space(ch)):
            out.append(ch)
        else:
            out.append("<U+{:04X}>".format(ord(ch)))
    return "".join(out)


def limit_input(text: str, max_chars: int = MAX_INPUT_CHARS) -> Tuple[str, bool]:
    """Sanitize user input and cap its length. Returns (text, was_truncated)."""
    clean = strip_unsafe(text).strip()
    if len(clean) > max_chars:
        return clean[:max_chars], True
    return clean, False


# ---------------------------------------------------------------- redaction

def _p(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


_SECRET_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (_p(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), "[REDACTED_PRIVATE_KEY]"),
    (_p(r"\b(?:sk|pk|rk)-[A-Za-z0-9_\-]{16,}"), "[REDACTED_KEY]"),
    (_p(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_KEY]"),
    (_p(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}"), "[REDACTED_KEY]"),
    (_p(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_KEY]"),
    (_p(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED_KEY]"),
    (_p(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[REDACTED_TOKEN]"),
    (_p(r"\b(bearer)\s+[A-Za-z0-9._~+/=\-]{16,}", re.I), r"\1 [REDACTED]"),
    (_p(r"\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)", re.I),
     r"\1\2[REDACTED]"),
    (_p(r"://[^/\s:@]+:[^/\s@]+@"), "://[REDACTED]@"),
    (_p(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (_p(r"(/home/|/Users/)[^/\s]+", re.I), r"\1<user>"),
    (_p(r"([A-Za-z]:\\Users\\)[^\\\s]+", re.I), r"\1<user>"),
]

_IP_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (_p(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[IP]"),
    (_p(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"), "[IPV6-OR-MAC]"),
]


def _apply(text: str, patterns: List[Tuple[Pattern[str], str]]) -> Tuple[str, int]:
    total = 0
    for pattern, repl in patterns:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def redact(text: str, redact_ips: bool = True) -> Tuple[str, int]:
    """Best-effort removal of secrets, emails, user names in paths and (optionally) IPs.

    Returns (redacted_text, number_of_items_redacted). Not a guarantee: regexes
    cannot recognize every secret, which is why cloud mode asks for consent first.
    """
    text, n = _apply(text, _SECRET_PATTERNS)
    if redact_ips:
        text, m = _apply(text, _IP_PATTERNS)
        n += m
    return text, n
