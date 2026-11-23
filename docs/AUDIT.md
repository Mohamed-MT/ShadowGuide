# Security audit report: ShadowGuide 0.3.0

**Type:** internal audit (design review, static analysis, fuzzing, red-team testing, supply-chain review) performed by the author with automated tooling.
**This is not an independent third-party audit or penetration test.** See "What this audit does not cover".

## 1. Scope
All code under `src/shadowguide`, the build and release pipeline (`.github/`, `pyproject.toml`, `requirements-dev.lock`, `scripts/`), and the documentation's security claims. Security objectives: the tool never executes anything, never stores anything, never leaks keys or data, never lets model output or pasted text act on the user's terminal, and ships a trustworthy package.

## 2. Method
1. Threat modeling against the OWASP Top 10 for LLM Applications (2025) and published terminal-injection research (escape sequences, OSC 52 clipboard writes, bidirectional-text spoofing). See THREAT_MODEL.md.
2. Static analysis: Ruff (correctness, bugbear, security, simplify rules), Bandit, mypy `--strict`.
3. Architecture guard tests that fail the build if code gains execution, disk-write or extra network capability.
4. Property-based fuzzing (Hypothesis) of every parser and of the full pipeline with hostile model replies and hostile user input.
5. Red-team test of the risk engine: 65 must-flag commands, each run through 18 evasion transformations (1,170 checks), plus 59 everyday commands to watch for false positives.
6. Hostile-endpoint tests with an in-process HTTP server (redirects, oversized replies, malformed JSON, slow-drip replies, error bodies containing secrets).
7. Supply-chain review: dependencies, CI permissions, action pinning, build contents, release path.
8. Manual code review of every module.

## 3. Results of automated checks (this release)
| Check | Result |
|---|---|
| Ruff (E,F,W,B,S,SIM,RET,PLE,PLW,C4,PIE,RUF) | clean |
| mypy `--strict` | clean, 14 source files |
| Bandit | 0 findings |
| Tests | 242 passing (also with Python warnings treated as errors) |
| Coverage | 96.3% line + branch (gate: 92%) |
| Fuzz soak | 13 properties x 2,000 examples x 3 fresh seeds, all passing (about 78,000 generated cases) |
| pip-audit on the hash-pinned dev lock | no known vulnerabilities |
| Runtime dependencies | none |
| actionlint on all workflows | clean |
| `twine check --strict`, `scripts/check_dist.py` | pass; wheel contains only the package, `py.typed` and the license |
| Secret scan of source, docs and config | nothing found |

## 4. Findings
Severity is the author's estimate of impact had the issue shipped. All findings below are fixed unless stated.

| # | Finding | Found by | Severity | Status |
|---|---|---|---|---|
| 1 | `urllib` forwards auth headers across redirects, which could leak an API key to another host | design review | High | Fixed: redirects refused; test |
| 2 | Escape sequences in model output could write to the clipboard (OSC 52) or rewrite the screen | design review, research | High | Fixed: stripped everywhere; commands containing them withheld; fuzz-proven |
| 3 | Bidirectional and zero-width characters could disguise a command | design review, research | High | Fixed: stripped, withheld, flagged, escaped in display |
| 4 | Unicode "tag" characters could smuggle hidden instructions into prompts | research | High | Fixed: stripped from all input and output |
| 5 | The network function trusted its callers to validate the URL scheme (file:, ftp:) | Ruff S310 | Medium | Fixed: the function enforces policy itself; test |
| 6 | Total-deadline protection against slow-drip servers was ineffective: `read(n)` blocks until n bytes arrive | new hostile-server test | Medium | Fixed with `read1()`; test |
| 7 | Wrapper evasion: `bash -c 'reboot'`, `env shutdown`, `nohup reboot` rated LOW | red-team mutation test | High | Fixed |
| 8 | Terminator evasion: `rm -rf /;` and `$(rm -rf /)` rated HIGH instead of CRITICAL | red-team mutation test | Medium | Fixed |
| 9 | Whitespace evasion in the `nmap --script` rule (tabs, repeated spaces) | red-team mutation test | Low | Fixed |
| 10 | Risk coverage gaps: backup deletion, raw-disk writes, Windows/macOS destructive tools, traffic-capture tools, security-control changes | review | Medium | Fixed: 16 new rule groups added (69 total) |
| 11 | Deeply nested JSON from a model crashed the parser (`RecursionError`) | adversarial probing | Medium | Fixed in parser and HTTP layer; test |
| 12 | Key and model-name validators used `$` anchoring, which accepts a trailing newline | adversarial probing | Low | Fixed with full-match; test |
| 13 | Type hole: an optional key was passed where a key was required | mypy | Low | Fixed |
| 14 | The API key was requested before the user had seen what would be sent | manual review | Medium | Fixed: consent first, key second |
| 15 | HTTP error responses kept connections open until garbage collection | warnings-as-errors run | Low | Fixed; regression test |
| 16 | `--shell` value flowed unvalidated into the model prompt | manual review | Low | Fixed: strict short-name validation |
| 17 | Environment text was not marked as data in the system prompt | manual review | Low | Fixed |
| 18 | `doctor` output could expose the user name through file paths | manual review | Low | Fixed: home directory masked |
| 19 | An unexpected exception could print a traceback or text containing secrets | manual review | Medium | Fixed: generic message; full trace only with `SHADOWGUIDE_DEBUG=1` |
| 20 | Regex denial of service in risk rules | probing | Medium | Verified safe: 100 KB hostile input in about 0.2 s; test |
| 21 | Hostile URLs (`127.0.0.1.evil.com`, userinfo tricks, decimal IPs) | probing | Medium | Verified rejected; tests |
| 22 | Unbounded memory and cost (history, responses, cloud requests) | design review | Medium | Fixed: caps and session limit |
| 23 | Python 3.9 and 3.10 are end-of-life and were supported | review | Medium | Fixed: requires Python 3.11 or newer |
| 24 | License declared as MIT but no LICENSE file shipped | review | Low | Fixed |
| 25 | Supply chain: unpinned CI actions, unpinned dev dependencies, broad default token permissions | review | Medium | Fixed: actions pinned to commit SHAs, hash-locked dev dependencies, least-privilege permissions, CodeQL, Dependabot, provenance attestation on release |
| 26 | Bandit B604 (a keyword argument named `shell`) | Bandit | Info | False positive; removed by construction |

## 5. What this audit does not cover
- **No independent review.** A third-party penetration test and code review should happen before wide distribution.
- **Not run on real hardware matrices.** Tests ran on Linux. Windows and macOS are covered by the CI matrix once pushed. Behavior with real Ollama models and real cloud providers has not been exercised, only emulated servers.
- **The risk engine is heuristic.** It does not parse shell grammar. A determined author can still write a harmful command it rates LOW. The corpus and mutations raise the bar but cannot prove absence of bypasses. Mutation testing of the test suite itself was not performed.
- **Workflows were validated, not executed.** `actionlint` and YAML checks pass, but GitHub-hosted runs have not happened. Action versions were resolved live from GitHub at audit time; verify them when you create the repository.
- **Repository controls are the owner's job** (branch protection, secret scanning, two-factor authentication, trusted publisher setup). See docs/REPO_HARDENING.md.
- **Trusted components:** the Python runtime and its TLS stack, the operating system trust store, the user's own Ollama installation, and the cloud provider the user chooses.
- **AI correctness.** Models can give wrong or incomplete advice. The product mitigates but cannot eliminate this.

## 6. Release readiness
Suitable for a public release candidate once the owner (a) pushes to a repository and gets the CI matrix green on all three operating systems, (b) completes docs/REPO_HARDENING.md, and (c) tries it with a real local model and a real API key. Recommended before calling it 1.0: independent penetration test, an offline knowledge base to reduce invented flags, and continued growth of the risk-rule corpus from real user reports.
