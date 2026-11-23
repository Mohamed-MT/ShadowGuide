"""Terminal rendering. ASCII-only structure so it works in every console.

Color is an enhancement, never the only signal: every risk level also has a text
label. Only ShadowGuide's own color codes are ever emitted; all model text has
already had escape sequences stripped.
"""
from __future__ import annotations

import os
import shutil
import textwrap
from typing import List, Mapping, Optional, Sequence, TextIO

from .prompt import Reply
from .risk import Assessment, Level, advice_for, classify
from .sanitize import escape_for_display

ADVISORY_NOTE = "ShadowGuide never runs commands. Review each one, then copy and run it yourself."

_BANNERS = {
    Level.CRITICAL: "!! CRITICAL DANGER: this can cause severe damage that is often impossible to undo. "
                    "Do not run it unless you fully understand every part. !!",
    Level.HIGH: "!! HIGH RISK: this can delete data, weaken security or disrupt your system. "
                "Read the warnings below before doing anything. !!",
}


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return "\x1b[{}m{}\x1b[0m".format(code, text) if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def level(self, level: Level, t: str) -> str:
        code = {Level.LOW: "32", Level.MEDIUM: "33", Level.HIGH: "1;31", Level.CRITICAL: "1;97;41"}[level]
        return self._wrap(code, t)

    def red(self, t: str) -> str:
        return self._wrap("1;31", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)


def supports_color(stream: TextIO, env: Mapping[str, str], disabled: bool = False) -> bool:
    if disabled or env.get("NO_COLOR"):
        return False
    if env.get("FORCE_COLOR") not in (None, "", "0"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty() or env.get("TERM") == "dumb":
        return False
    if os.name == "nt":  # legacy consoles may not interpret ANSI; modern terminals announce themselves
        return bool(env.get("WT_SESSION") or env.get("ANSICON") or env.get("ConEmuANSI") == "ON"
                    or env.get("TERM_PROGRAM") or env.get("TERM"))
    return True


def terminal_width(default: int = 80) -> int:
    return max(40, min(shutil.get_terminal_size((default, 24)).columns, 100))


def _para(text: str, width: int, indent: str = "  ", bullet: str = "") -> List[str]:
    lines: List[str] = []
    for raw in text.splitlines() or [""]:
        lines.append(textwrap.fill(raw, width=width, initial_indent=indent + bullet,
                                   subsequent_indent=indent + " " * len(bullet)) or "")
    return lines


def command_block(header: str, command: str, assessment: Assessment, style: Style, width: int,
                  explanation: str = "", cautions: Sequence[str] = (), prerequisites: Sequence[str] = (),
                  alternatives: Sequence[str] = ()) -> List[str]:
    level = assessment.level
    tag = "[ RISK: {} ]".format(level.name)
    rule = "-" * width
    lines = [rule, header + " " * max(1, width - len(header) - len(tag)) + style.level(level, tag), rule]

    for line in escape_for_display(command).split("\n"):
        lines.append("    " + (style.red(line) if assessment.dangerous else style.bold(line)))
    lines.append("")

    if assessment.dangerous:
        for line in textwrap.wrap(_BANNERS[Level.CRITICAL if level == Level.CRITICAL else Level.HIGH], width - 2):
            lines.append(" " + style.level(level, " " + line.ljust(width - 3)))
        lines.append("")

    if explanation:
        lines += [style.bold("  What it does:"), *_para(explanation, width, "    "), ""]

    if assessment.findings:
        title = "Why this is dangerous:" if assessment.dangerous else "Be careful:"
        lines.append(style.bold("  " + title))
        for f in assessment.findings:
            lines += _para("[{}] {}".format(f.category, f.why), width, "    ", "* ")
        lines.append("")
        advice = []
        for f in assessment.findings:
            tip = advice_for(f.category)
            if tip not in advice:
                advice.append(tip)
        lines.append(style.bold("  How to reduce the risk:"))
        for tip in advice:
            lines += _para(tip, width, "    ", "- ")
        lines.append("")
    else:
        lines += [*_para("No known risky pattern matched. That is not a guarantee, so read it before you run it.", width, "  "), ""]

    if cautions:
        lines.append(style.bold("  Also keep in mind:"))
        for c in cautions:
            lines += _para(c, width, "    ", "- ")
        lines.append("")
    if prerequisites:
        lines.append(style.bold("  Before you run it:"))
        for p in prerequisites:
            lines += _para(p, width, "    ", "- ")
        lines.append("")
    if alternatives:
        lines.append(style.bold("  Alternatives:"))
        for alt in alternatives:
            level_alt = classify(alt).level
            tag_alt = "" if level_alt == Level.LOW else "  [risk: {}]".format(level_alt.name)
            lines += _para(alt + tag_alt, width, "    ", "- ")
        lines.append("")
    return lines


def render_reply(reply: Reply, style: Style, width: Optional[int] = None) -> str:
    width = width or terminal_width()
    out: List[str] = []
    if reply.answer:
        out += [style.bold("ANSWER"), *_para(reply.answer, width), ""]
    total = len(reply.commands)
    dangerous = 0
    for i, s in enumerate(reply.commands, 1):
        assessment = classify(s.command)
        dangerous += assessment.dangerous
        out += command_block("COMMAND {} of {}".format(i, total), s.command, assessment, style, width,
                             s.explanation, s.cautions, s.prerequisites, s.alternatives)
    if reply.notes:
        out += [style.bold("NOTES"), *_para(reply.notes, width), ""]
    for reason in reply.withheld:
        out += [*_para("Withheld: " + reason, width, "", ""), ""]
    if dangerous:
        out.append(style.red("Heads-up: {} of {} suggested command(s) are high risk or worse. "
                             "Read the warnings above before doing anything.".format(dangerous, total)))
    if total:
        out.append(style.dim(ADVISORY_NOTE))
    return "\n".join(out).rstrip()


def render_check(command: str, style: Style, width: Optional[int] = None) -> str:
    width = width or terminal_width()
    return "\n".join(command_block("COMMAND CHECK", command, classify(command), style, width)).rstrip()
