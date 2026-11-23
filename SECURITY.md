# Security

## Supported versions
Only the latest release receives security fixes. ShadowGuide requires Python 3.11 or newer (older versions are end-of-life).

## Reporting a vulnerability
Use GitHub's **private vulnerability reporting** (repository Security tab, "Report a vulnerability") and do not open a public issue. Include steps to reproduce and the output of `shadowguide --version`. Targets: acknowledgement within 7 days, a fix or mitigation plan within 30 days, and coordinated public disclosure with credit if you want it.

In scope: anything that lets text from a model, a user, a network peer or a file cause code execution, file writes, key disclosure, terminal manipulation, or a dangerous command to be rated LOW without a plausible reason. Out of scope: a determined human deliberately writing a command the heuristic rates LOW, with no safer-by-default fix (please still report; it improves the rules).

## Design principles
1. **No agency.** The program cannot run commands, spawn processes, or write files. This is enforced structurally (no such code exists) and by tests that scan the source for execution primitives, disk writes and network imports.
2. **Model output is untrusted data** (OWASP LLM05 Improper Output Handling). Replies are parsed against a fixed schema, stripped of terminal escape sequences and invisible characters, length-limited, and rated by an independent rule engine.
3. **Least privilege and least data.** One network module; loopback-only for local mode; HTTPS-only for cloud; nothing stored; minimal data sent.
4. **Human in the loop.** The user reads and runs every command. Dangerous commands are shown in red with explanations.

## Mapping to the OWASP Top 10 for LLM Applications (2025)
| Risk | Mitigation |
|---|---|
| LLM01 Prompt injection | Pasted content is declared to be data in the system prompt; hidden Unicode ("ASCII smuggling") and escape sequences are stripped from input; no tools or actions exist for an injection to abuse; independent risk engine and human review backstop bad advice |
| LLM02 Sensitive information disclosure | Nothing stored; cloud mode needs consent and redacts secrets, emails, user names and IPs |
| LLM03 Supply chain | Zero runtime dependencies; hash-locked dev dependencies; CI actions pinned to commit SHAs with least-privilege permissions; CodeQL, Dependabot, signed build provenance |
| LLM05 Improper output handling | Strict parsing, sanitization, escaping of hidden characters, command withholding, rule-based risk rating, ASCII-only layout |
| LLM06 Excessive agency | No execution, no file writes, no install capability; the assistant is told to prefer built-in tools and the risk engine flags any software installation |
| LLM07 System prompt leakage | The prompt contains no secrets; leaking it reveals nothing sensitive |
| LLM09 Misinformation | The model is told to admit uncertainty and point to `--help`; risk ratings are independent; docs state the limits |
| LLM10 Unbounded consumption | Input cap, reply and response size caps, command-count cap, timeouts plus a total request deadline, bounded history, per-session request cap in cloud mode |

## Terminal-output hardening
Terminals interpret in-band control sequences, so output is untrusted. ShadowGuide strips ANSI/CSI/OSC/DCS sequences (including OSC 52 clipboard writes), control characters, bidirectional overrides, zero-width and tag characters, variation selectors and unusual spaces from everything it displays, withholds any suggested command that contains them, flags look-alike letters from other alphabets, flags multi-line commands (which can run on paste), and uses only ASCII for its own layout.

## Network hardening
The single network function enforces policy itself: HTTPS required (plain http only for loopback), no other URL schemes, no credentials inside URLs, redirects refused (so credentials cannot be forwarded to another host), TLS 1.2+ with certificate verification, response size capped, a total deadline that also stops slow-drip replies, connections always closed, and error messages sanitized so they never contain keys. In cloud mode, consent is requested before the key is asked for.

## Build and release hardening
Hash-locked dev dependencies (`requirements-dev.lock`, installed with `--require-hashes`), CI actions pinned to full commit SHAs, per-job least-privilege permissions, checkout without persisted credentials, CodeQL, Dependabot, `pip-audit`, wheel/sdist content verification (`scripts/check_dist.py`), clean-environment install test, and releases published through Trusted Publishing with signed provenance (no stored tokens).

## Automated guards (run in CI on every platform)
`tests/test_architecture_guards.py` fails the build if source code imports process, dynamic-loading or serialization modules, calls `eval`/`exec`, writes to disk, or uses network libraries outside `backends/http.py`. Property-based fuzz tests assert that no input can make the program emit terminal control sequences or hidden characters, and a red-team suite checks that evasion tricks never lower a command's risk rating. The full audit is in docs/AUDIT.md.

## Scope and limits
See THREAT_MODEL.md for residual risks, notably: the risk engine is heuristic and can be evaded by a determined author; AI answers can be wrong; and a compromised OS or terminal is out of scope.
