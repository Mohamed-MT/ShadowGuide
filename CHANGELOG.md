# Changelog

## 0.3.0
Security audit and hardening release. See docs/AUDIT.md for all 26 findings.
- Network layer: enforces URL policy itself, total request deadline (stops slow-drip replies), connections always closed.
- Risk engine: 16 new rule groups (69 total); fixes for wrapper, terminator and whitespace evasions found by the new red-team suite.
- Cloud mode: consent is requested before the API key is asked for; stricter input validation (`--shell`).
- Reliability and privacy: no tracebacks on unexpected errors, home directory masked in `doctor`.
- Testing: 242 tests including property-based fuzzing, a red-team evasion suite, hostile-server tests, 92% coverage gate; mypy strict, Ruff, Bandit clean.
- Supply chain: hash-locked dev dependencies, CI actions pinned to commit SHAs, least-privilege permissions, CodeQL, Dependabot, signed provenance on release, verified distribution contents.
- Requires Python 3.11 or newer (older versions are end-of-life). Added LICENSE.

## 0.2.0
Two backends (local Ollama, own API key), red danger display, sanitization, architecture guard tests.
