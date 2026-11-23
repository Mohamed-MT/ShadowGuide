# Privacy

ShadowGuide is built so that there is nothing to leak.

## What is stored
Nothing. No history, logs, cache, config file, or API key is written to disk. Every session starts clean. Closing the program discards the conversation. (A test fails the build if any code writes to disk.)

## Accounts, payments, telemetry
None. No sign-in, no payment, no analytics, no crash reporting, no update checks.

## Local mode (default)
ShadowGuide connects only to Ollama on your own machine (`127.0.0.1`, `localhost` or `::1`; anything else is refused). System proxy settings are ignored for these connections. Your questions never leave the computer.

## Cloud mode (only if you choose it)
You opt in with `--backend openai` or `--backend anthropic`. After you confirm, ShadowGuide sends over HTTPS to the provider you chose:

- your questions (after redaction, below), and
- a short environment summary: OS name and version, architecture, shell, terminal, and the names (not paths) of notable tools found on your PATH.

It does not send file contents, file paths, your user name, or your hostname. The provider's own privacy and retention policy applies to what it receives; read it before using cloud mode.

### Redaction (best-effort)
Before sending, ShadowGuide replaces API keys and tokens, passwords in `key=value` form, private key blocks, credentials in URLs, email addresses, user names in `/home/...`, `/Users/...` and `C:\Users\...` paths, and IP addresses (keep IPs with `--keep-ips`). Pattern matching cannot recognize every secret, so **do not paste secrets or sensitive logs**.

### Your API key
Read from `SHADOWGUIDE_API_KEY`, `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, or typed at a hidden prompt. Never accepted as a command-line flag, never written to disk, never printed or logged, and held only in memory for the session. Note: an environment variable is visible to other processes running as your user, and Python cannot guarantee wiping memory.

## Commands
ShadowGuide never executes commands, on any backend.
