"""Command-line interface. Prints guidance only; never runs anything."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import __version__
from .backends import (ANTHROPIC_DEFAULT_BASE, BACKEND_CHOICES, DEFAULT_URL, OPENAI_DEFAULT_BASE, Backend,
                       BackendError, Secret, create_backend)
from .backends.http import is_loopback_url, validate_url
from .env import Environment, detect_environment
from .prompt import HISTORY_LIMIT, MAX_HISTORY_REPLY, Reply, build_system_prompt, parse_reply, trim_history
from .render import ADVISORY_NOTE, Style, render_check, render_reply, supports_color
from .sanitize import limit_input, redact, strip_unsafe

MAX_CLOUD_REQUESTS = 100  # per session; guards against runaway API costs

PRIVACY_SUMMARY = """ShadowGuide privacy summary
  Stored on disk:    nothing. No history, logs, config files or keys. Every session starts clean.
  Accounts/payments: none. No telemetry, analytics or update checks.
  Local mode:        talks only to Ollama on this machine (127.0.0.1 / localhost).
  Cloud mode:        only if you choose --backend openai|anthropic. After you confirm, your questions
                     and a short environment summary (OS, shell, terminal, tool names) are sent over
                     HTTPS to that provider. Secrets, emails, user names in paths and IPs are redacted
                     first, best-effort. Your API key stays in memory for this session only.
  Commands:          ShadowGuide never executes anything. You run commands yourself."""

_KEY_ENV: Dict[str, Tuple[str, ...]] = {
    "openai": ("SHADOWGUIDE_API_KEY", "OPENAI_API_KEY"),
    "anthropic": ("SHADOWGUIDE_API_KEY", "ANTHROPIC_API_KEY"),
}


# ------------------------------------------------------------------ core logic

def prepare_user_text(text: str, backend: Backend, keep_ips: bool) -> Tuple[str, int, bool]:
    clean, truncated = limit_input(text)
    redacted = 0
    if not backend.is_local:
        clean, redacted = redact(clean, redact_ips=not keep_ips)
    return clean, redacted, truncated


def ask_backend(backend: Backend, system: str, history: List[Dict[str, str]], user_text: str,
                keep_ips: bool = False) -> Tuple[Reply, int, bool]:
    text, redacted, truncated = prepare_user_text(user_text, backend, keep_ips)
    if not text:
        raise BackendError("Please type a question.")
    raw = backend.generate(system, [*trim_history(history), {"role": "user", "content": text}])
    history.append({"role": "user", "content": text})
    history.append({"role": "assistant", "content": strip_unsafe(raw)[:MAX_HISTORY_REPLY]})
    del history[:-2 * HISTORY_LIMIT]  # memory stays bounded in long sessions
    return parse_reply(raw), redacted, truncated


def _notices(redacted: int, truncated: bool) -> List[str]:
    out = []
    if truncated:
        out.append("(Your input was shortened to the safety limit.)")
    if redacted:
        out.append("(Redacted {} sensitive item(s) before sending.)".format(redacted))
    return out


def chat_loop(backend: Backend, env: Environment, style: Style, keep_ips: bool = False,
              read: Callable[[str], str] = input, write: Callable[[str], None] = print) -> int:
    system = build_system_prompt(env)
    history: List[Dict[str, str]] = []
    requests = 0
    write("ShadowGuide {} | {} {} | shell: {} | {}".format(
        __version__, env.os_name, env.os_version, env.shell.value, backend.describe()))
    if env.shell.confidence != "high":
        write("Detected shell: {} ({} confidence). If that is wrong, restart with --shell (e.g. --shell powershell)."
              .format(env.shell.value, env.shell.confidence))
    if not backend.is_local:
        write(style.yellow("CLOUD MODE: questions go to " + backend.destination + " (redacted first)."))
    write(ADVISORY_NOTE)
    write("Ask in plain English. /env  /privacy  /clear  /help  /quit\n")
    while True:
        try:
            line = read("shadowguide> ").strip()
        except EOFError:
            write("")
            return 0
        if not line:
            continue
        cmd = line.lower()
        if cmd in ("/quit", "/exit", "quit", "exit"):
            return 0
        if cmd == "/help":
            write("/env      show what was detected\n/privacy  what is stored and sent\n"
                  "/clear    forget this conversation\n/quit     exit\nAnything else is a question.\n")
            continue
        if cmd == "/env":
            write(env.prompt_summary() + "\n")
            continue
        if cmd == "/privacy":
            write(PRIVACY_SUMMARY + "\n")
            continue
        if cmd == "/clear":
            history.clear()
            write("Conversation cleared.\n")
            continue
        if not backend.is_local and requests >= MAX_CLOUD_REQUESTS:
            write("Session request limit reached. Restart ShadowGuide to continue (this protects your API budget).")
            return 0
        try:
            reply, redacted, truncated = ask_backend(backend, system, history, line, keep_ips)
        except BackendError as exc:
            write("error: {}\n".format(exc))
            continue
        requests += 1
        for note in _notices(redacted, truncated):
            write(note)
        write("\n" + render_reply(reply, style) + "\n")


# ---------------------------------------------------------- backend selection

def get_api_key(name: str, env: Dict[str, str], interactive: bool,
                prompt: Callable[[str], str] = getpass.getpass) -> Optional[Secret]:
    """Keys come from the environment or a hidden prompt, never from a command-line flag."""
    for var in _KEY_ENV[name]:
        if env.get(var):
            return Secret(env[var].strip())
    if interactive:
        value = prompt("API key (hidden; kept in memory for this session only): ").strip()
        if value:
            return Secret(value)
    return None


def confirm_cloud(destination: str, env: Environment, accept: bool, keep_ips: bool, interactive: bool,
                  read: Callable[[str], str] = input, write: Callable[[str], None] = print) -> None:
    write(f"CLOUD MODE: your questions will be sent over HTTPS to {destination} using your API key.")
    write("What is sent: your questions, plus this environment summary:")
    for line in env.prompt_summary().splitlines():
        write("    " + line)
    write("Before sending, ShadowGuide redacts API keys, tokens, passwords, emails, user names in paths"
          + ("" if keep_ips else " and IP addresses") + ". Redaction is best-effort, so do not paste secrets.")
    write("The provider's own data policy applies. ShadowGuide saves nothing.\n")
    if accept:
        return
    if not interactive:
        raise BackendError("Cloud mode needs your confirmation. Re-run with --accept-cloud to agree.")
    if read("Type 'yes' to continue: ").strip().lower() != "yes":
        raise BackendError("Cancelled. Nothing was sent.")


_DEFAULT_BASES = {"openai": OPENAI_DEFAULT_BASE, "anthropic": ANTHROPIC_DEFAULT_BASE}


def build_backend(args: argparse.Namespace, env: Environment) -> Backend:
    interactive = sys.stdin.isatty()
    model = args.model or os.environ.get("SHADOWGUIDE_MODEL")
    key = None
    if args.backend != "ollama":
        # Order matters: validate everything and get consent BEFORE asking for the key.
        if not model:
            raise BackendError("Cloud backends need a model name: --model <name> (or set SHADOWGUIDE_MODEL).")
        base = validate_url(args.base_url or _DEFAULT_BASES[args.backend])
        local = is_loopback_url(base)
        if not local:
            confirm_cloud(urlparse(base).hostname or "unknown host", env, args.accept_cloud, args.keep_ips, interactive)
        key = get_api_key(args.backend, dict(os.environ), interactive and not local)
        if key is None and not local:
            raise BackendError("No API key found. Set {} in your environment, or run interactively to be asked. "
                               "Keys are never accepted as command-line options and are never stored."
                               .format(_KEY_ENV[args.backend][1]))
    backend = create_backend(args.backend, model, host=args.host, base_url=args.base_url, key=key)
    note = backend.prepare()
    if note:
        print(note)
    return backend


# --------------------------------------------------------------- subcommands

def _style(args: argparse.Namespace) -> Style:
    return Style(supports_color(sys.stdout, os.environ, disabled=args.no_color))


def _env(args: argparse.Namespace) -> Environment:
    try:
        return detect_environment(shell_override=args.shell)
    except ValueError as exc:
        raise BackendError(str(exc)) from None


def _mask_home(path: str) -> str:
    """Keep user names out of output that people may paste into bug reports."""
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if home not in ("~", "", os.sep) and path.startswith(home) else path


def cmd_ask(args: argparse.Namespace) -> int:
    env, style = _env(args), _style(args)
    backend = build_backend(args, env)
    reply, redacted, truncated = ask_backend(backend, build_system_prompt(env), [], " ".join(args.question), args.keep_ips)
    for note in _notices(redacted, truncated):
        print(note)
    print(render_reply(reply, style))
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    env, style = _env(args), _style(args)
    backend = build_backend(args, env)
    return chat_loop(backend, env, style, args.keep_ips)


def cmd_doctor(args: argparse.Namespace) -> int:
    env = _env(args)
    print("ShadowGuide {} environment report\n".format(__version__))
    print("OS:        {} {} ({})".format(env.os_name, env.os_version, env.arch) + (" [WSL]" if env.wsl else ""))
    if env.distro_id:
        print("Distro ID: " + env.distro_id)
    print("Shell:     {} [{} confidence: {}]".format(env.shell.value, env.shell.confidence, env.shell.source))
    print("Terminal:  {} [{}]".format(env.terminal.value, env.terminal.source))
    print("\nTools found on PATH:")
    for name, path in sorted(env.tools.items()):
        print("  {:<12} {}".format(name, _mask_home(path)))
    print("\nBackend:   " + args.backend)
    if args.backend == "ollama":
        print("Checking local Ollama at {} (the only connection doctor makes)...".format(args.host))
        try:
            names = create_backend("ollama", None, host=args.host).list_models()
            print("Ollama is running. Models: " + (", ".join(names) or "none installed (try: ollama pull llama3.2)"))
        except BackendError as exc:
            print(str(exc))
    else:
        print("Cloud backends are not contacted by doctor. Set your key in the environment or enter it when asked.")
    return 0


def cmd_risk(args: argparse.Namespace) -> int:
    command = " ".join(args.command)
    if not command.strip():
        print("usage: shadowguide risk <command to check>", file=sys.stderr)
        return 2
    print(render_check(command, _style(args)))
    return 0


def cmd_privacy(args: argparse.Namespace) -> int:
    print(PRIVACY_SUMMARY)
    return 0


# ------------------------------------------------------------------- parsing

def _add_common(parser: argparse.ArgumentParser, sub: bool) -> None:
    def d(value: Any) -> Any:
        return argparse.SUPPRESS if sub else value
    parser.add_argument("--backend", choices=BACKEND_CHOICES, default=d("ollama"),
                        help="ollama (local, default) or openai / anthropic (your own API key)")
    parser.add_argument("--model", default=d(None), help="model name (env: SHADOWGUIDE_MODEL). Required for cloud backends")
    parser.add_argument("--host", default=d(DEFAULT_URL), help="local Ollama URL (loopback only)")
    parser.add_argument("--base-url", default=d(None), help="custom API endpoint for openai-compatible or anthropic backends (https)")
    parser.add_argument("--shell", default=d(None), help="override shell detection (bash, zsh, powershell, cmd, ...)")
    parser.add_argument("--no-color", action="store_true", default=d(False), help="disable colors")
    parser.add_argument("--accept-cloud", action="store_true", default=d(False),
                        help="agree to cloud mode without the interactive prompt")
    parser.add_argument("--keep-ips", action="store_true", default=d(False), help="do not redact IP addresses in cloud mode")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowguide", allow_abbrev=False,
        description="Local-first, advisory-only terminal companion. It explains commands and never runs them.",
        epilog="API keys: set SHADOWGUIDE_API_KEY (or OPENAI_API_KEY / ANTHROPIC_API_KEY) or enter it when asked. "
               "Keys are never accepted as flags and never stored.")
    parser.add_argument("--version", action="version", version="shadowguide " + __version__)
    _add_common(parser, sub=False)
    subs = parser.add_subparsers(dest="cmd")
    for name, func, help_text in (
        ("ask", cmd_ask, "ask one question and exit"),
        ("chat", cmd_chat, "interactive assistant (default)"),
        ("doctor", cmd_doctor, "show what ShadowGuide detected about your environment"),
        ("risk", cmd_risk, "risk-check a command offline, without any model"),
        ("privacy", cmd_privacy, "what is stored and what is sent"),
    ):
        p = subs.add_parser(name, help=help_text, allow_abbrev=False)
        _add_common(p, sub=True)
        p.set_defaults(func=func)
        if name == "ask":
            p.add_argument("question", nargs="+")
        if name == "risk":
            p.add_argument("command", nargs=argparse.REMAINDER, help="the command to check (everything after 'risk')")
    return parser


def _quiet_exit() -> None:
    """The reader closed the pipe (e.g. `| head`). Exit without a traceback."""
    os._exit(0)


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # never crash on an unencodable character
    args = build_parser().parse_args(argv)
    func = getattr(args, "func", cmd_chat)
    try:
        return func(args)
    except BackendError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    except BrokenPipeError:
        _quiet_exit()
        return 0
    except Exception as exc:  # last line of defense: never dump a traceback or exception text
        if os.environ.get("SHADOWGUIDE_DEBUG"):
            raise
        print(f"error: unexpected internal error ({type(exc).__name__}). Set SHADOWGUIDE_DEBUG=1 for details.", file=sys.stderr)
        return 70
