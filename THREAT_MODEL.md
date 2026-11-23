# Threat model

## What we protect
- **The user's machine**: nothing ShadowGuide outputs should be able to harm it without the user knowingly acting.
- **The user's API key** (cloud mode).
- **The user's questions and environment details.**
- **Integrity of what the user sees** (the command shown must be the command that gets pasted).

## Trust boundaries
user input -> ShadowGuide -> model backend (local loopback, or cloud over HTTPS) -> reply -> ShadowGuide parsing, sanitizing and rating -> terminal display -> **user's clipboard and shell (the user's own action)**.
ShadowGuide never crosses the last boundary: it does not execute, and it does not touch the clipboard.

## Adversaries
A. A malicious, compromised or hallucinating model. B. Hostile text the user pastes (logs, web pages, tool output). C. A network attacker or malicious proxy. D. Another local user or process on the same machine. E. A supply-chain attacker. F. A person trying to use the tool to get attack help. G. The cloud provider.

## Threats and mitigations
| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | Model suggests a destructive or privileged command | Independent rule-based rating; red banner, explanation and risk-reduction tips; no execution | Rules are heuristic; creative obfuscation can evade them. Human review is the final control |
| 2 | Model emits terminal escape sequences (e.g. OSC 52 clipboard write, cursor tricks) | All escapes and control characters stripped; commands containing them withheld; ASCII-only layout | Terminal-specific quirks we have not anticipated |
| 3 | Bidi/zero-width/look-alike characters make a command look different from what it executes | Stripped from prose; commands containing them withheld; hidden characters shown as `<U+XXXX>`; look-alike alphabets flagged | Look-alikes outside the checked scripts |
| 4 | Prompt injection through pasted content | System prompt treats pasted text as data; hidden-Unicode smuggling stripped; model has no tools; output validated and rated | A model can still be misled into bad advice; rating and human review backstop |
| 5 | Excessive agency (model causes actions) | No execution, file-write or install code exists; enforced by tests | None by design |
| 6 | Multi-line paste runs immediately | Multi-line commands flagged with advice to paste into an editor first | Users can ignore the warning |
| 7 | API key theft or leakage | Environment or hidden prompt only; never a flag; never stored/printed/logged; strict key format (blocks header injection); HTTPS only; no redirects; sanitized errors | Env vars readable by same-user processes; memory not wiped; malware on the host defeats this |
| 8 | Sensitive data sent to the cloud | Opt-in with explicit consent showing what is sent; redaction; minimal environment summary | Redaction is pattern-based and can miss secrets; provider retention policy applies |
| 9 | Request redirection/SSRF/exfiltration via configurable URLs | Ollama loopback-only; cloud https-only; no URL credentials; redirects refused; single egress module | A user can deliberately point `--base-url` at a malicious HTTPS host (their choice) |
| 10 | Resource exhaustion or runaway cost | Input, reply, response and history caps; timeouts; 100 requests/session in cloud mode | A user can restart sessions |
| 11 | Dependency compromise | Zero runtime dependencies; dev dependencies hash-locked and scanned with pip-audit | Dev tooling only; never shipped |
| 12 | Misuse for attack help | System prompt refuses harmful intent, requires authorization reminders; offensive tools rated HIGH with scope warnings | Dual-use knowledge exists in public docs; a model can still explain tools |
| 13 | Wrong or invented flags | Model told to admit uncertainty and cite `--help`; docs state limits | Small models hallucinate; an offline knowledge base is planned |
| 14 | Data at rest | Nothing stored | None |
| 15 | Spoofed environment variables skew detection | Detection only affects advice quality, never security decisions; user can override with `--shell` | Wrong-shell commands |

| 16 | Hostile or slow endpoint holds the client open or floods it | Total request deadline checked on every read, 4 MB response cap, per-socket timeouts, no redirects | A user can point `--base-url` at a hostile host (their choice); worst case is a bounded delay |
| 17 | Compromise of the build or release pipeline | Actions pinned to commit SHAs; hash-locked dev dependencies; least-privilege job permissions; CodeQL; Dependabot; trusted publishing with signed provenance; wheel content verified in CI | Compromise of the maintainer's account or of GitHub itself; mitigated by 2FA, branch protection, required reviews (docs/REPO_HARDENING.md) |
| 18 | Resource leaks over long sessions | Connections closed on all paths; bounded history; tested with warnings as errors | None known |

## Out of scope
A compromised operating system, terminal emulator, Python runtime or Ollama installation; physical access; a user who pastes commands without reading them.

## Assumptions
The user runs commands themselves; the local Ollama server is the user's own; Python's TLS stack and the OS trust store are sound.
