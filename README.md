# ShadowGuide

**A local-first AI companion for your terminal.** Ask questions in plain English and get commands explained for your operating system and shell, along with what each command does, prerequisites, cautions, and alternatives.

ShadowGuide is advisory only: **it does not execute commands.** You review the suggestions and decide what to run yourself.

## What it does

- **Detects your environment** — identifies your operating system, version, shell, terminal, and selected tools available on your `PATH`.
- **Explains commands** — turns a plain-English question into structured guidance and suggested commands.
- **Checks command risk offline** — assigns LOW, MEDIUM, HIGH, or CRITICAL ratings using a separate, rule-based checker. The rating does not come from the AI model.
- **Handles model output defensively** — sanitizes terminal-control characters, validates the response format, and withholds commands containing certain hidden or unsafe characters.
- **Offers local or opt-in cloud AI** — use Ollama on your own machine by default, or connect to an API provider using your own key.

## Important safety note

ShadowGuide never runs a suggested command or installs software. Its risk checker is heuristic, not a guarantee: a LOW rating does **not** mean a command is safe, and dangerous commands can be missed. AI-generated guidance can also be inaccurate or incomplete. Read and understand every command before running it, especially commands that use administrator privileges, modify files, change security settings, or affect a network.

## Requirements

- Python **3.11 or newer**
- Windows, macOS, or Linux
- For local AI: [Ollama](https://ollama.com) installed and running, with a model downloaded
- For cloud AI: an API key for the provider you choose

ShadowGuide has **no third-party runtime Python dependencies**. Development and test tools are listed separately in `requirements-dev.lock`.


## Installation

Follow these steps to download and install ShadowGuide.

### Prerequisites

Before installing, make sure you have:
- Python installed.
- Git installed.

### Step 1: Clone the repository

Open a terminal (Command Prompt, PowerShell, or your preferred terminal) and run:

```bash
git clone https://github.com/Mohamed-MT/ShadowGuide.git
```

### Step 2: Navigate to the project directory

```bash
cd ShadowGuide
```

### Step 3: Install ShadowGuide

Run:

```bash
python -m pip install .
```

On Windows, if `python` is not recognized, try:

```bash
py -m pip install .
```

### Step 4: Verify the installation

Run:

```bash
shadowguide --help
```

If the installation was successful, the ShadowGuide command-line help should appear.

### Alternative: Install using pipx

You can also install ShadowGuide using [pipx](https://pipx.pypa.io/), which installs Python applications in isolated environments.

From the project directory, run:

```bash
pipx install .
```


After installation, the `shadowguide` command should be available in your terminal.

## Quick start: local AI with Ollama

Local Ollama is the default backend.

1. Install and start [Ollama](https://ollama.com).
2. Download a model. For example:

   ```bash
   ollama pull llama3.2
   ```

3. Start ShadowGuide:

   ```bash
   shadowguide
   ```

If you do not specify a model, ShadowGuide selects a model already installed in Ollama. You can choose one explicitly with `--model`:

```bash
shadowguide --model llama3.2
```

Once the model is installed, ShadowGuide communicates with Ollama through your machine's loopback interface. Downloading Ollama or a model may require an internet connection; local questions are sent to the local Ollama service, not to a cloud AI provider by ShadowGuide.

## Optional: use a cloud API

You can choose OpenAI, Anthropic, or an OpenAI-compatible API endpoint. You supply your own API key; ShadowGuide does not include one.

For example, to use OpenAI:

```bash
shadowguide --backend openai --model <model-name>
```

Or Anthropic:

```bash
shadowguide --backend anthropic --model <model-name>
```

If the appropriate API key is not already available in your environment, ShadowGuide asks for it using a hidden prompt when run interactively. Keys are not accepted as command-line arguments and are not saved to disk.

You can provide a key through `SHADOWGUIDE_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`. Avoid putting literal keys in shell commands or scripts that may be saved or shared.

For an OpenAI-compatible endpoint, provide its HTTPS base URL:

```bash
shadowguide --backend openai --base-url https://your-provider.example/v1 --model <model-name>
```

**Cloud privacy:** Before sending a request, ShadowGuide displays the destination and the information it plans to send, then asks you to confirm. It sends your question and a short environment summary. It attempts to redact secrets, email addresses, usernames in common home-directory paths, and IP addresses. Redaction is best-effort and cannot catch every sensitive value. Do not paste passwords, API keys, private data, or sensitive logs. The provider's own privacy and data-retention policies apply.

The `--accept-cloud` option skips the interactive confirmation. Use it only when you intentionally want to provide consent non-interactively.

See [PRIVACY.md](PRIVACY.md) for the full details.

## Commands

| Command | What it does |
|---|---|
| `shadowguide` | Start the interactive assistant |
| `shadowguide ask "question"` | Ask one question and exit |
| `shadowguide doctor` | Show detected environment details and check local Ollama availability |
| `shadowguide risk <command>` | Rate a command locally without contacting an AI model |
| `shadowguide privacy` | Display the privacy summary |
| `shadowguide --version` | Show the installed version |
| `shadowguide --help` | Show command-line options |

Examples:

```bash
shadowguide ask "Which process is using port 8080?"
shadowguide doctor
shadowguide risk rm -rf ./build
shadowguide --shell powershell ask "How do I list listening ports?"
```

### Interactive commands

While the assistant is running, use:

| Input | Action |
|---|---|
| `/help` | Show available interactive commands |
| `/env` | Show the detected environment summary |
| `/privacy` | Show what is stored and sent |
| `/clear` | Clear the current conversation from memory |
| `/quit` or `/exit` | Exit ShadowGuide |

### Useful options

- `--backend ollama|openai|anthropic` — select the AI backend. Ollama is the default.
- `--model <name>` — select a model.
- `--shell <name>` — override shell detection if it is incorrect or uncertain.
- `--host <url>` — set the local Ollama URL. Only loopback addresses are accepted.
- `--base-url <url>` — set a custom API endpoint. HTTPS is required for non-local endpoints.
- `--no-color` — disable colored output.
- `--keep-ips` — keep IP addresses in cloud requests instead of redacting them. Use with care.

Options can be placed before a subcommand, as in `shadowguide --shell powershell ask "..."`.

## Privacy and security

- No accounts, payments, telemetry, analytics, crash reporting, or update checks.
- No conversation history, logs, configuration, or API keys are written to disk by ShadowGuide.
- Local mode connects only to Ollama on the same machine.
- Cloud mode is optional and requires consent before requests are sent, unless you explicitly use `--accept-cloud`.
- API keys are read from supported environment variables or a hidden interactive prompt, held in memory for the session, and never accepted as command-line flags.
- Network requests are restricted to the dedicated network module. Non-local endpoints require HTTPS, redirects are refused, and responses are size-limited.
- Suggested commands are displayed for you to review; ShadowGuide does not execute them.

These protections reduce risk but cannot make the application, its dependencies, your computer, or AI-generated advice risk-free. Review the documentation below before using cloud mode or relying on a risk rating.

## Project documentation

- [PRIVACY.md](PRIVACY.md) — what ShadowGuide stores, sends, and redacts
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, threats, and residual risks
- [docs/REPO_HARDENING.md](docs/REPO_HARDENING.md) — GitHub account and repository settings to configure
- [docs/RELEASING.md](docs/RELEASING.md) — release and PyPI publishing process
- [CHANGELOG.md](CHANGELOG.md) — version history

## Development

Install the hash-pinned development dependencies and the project in editable mode:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps -e .
```

Run the tests and quality checks:

```bash
python -m pytest --cov
ruff check src tests
mypy
bandit -q -r src -c pyproject.toml
```

The test suite includes architecture guards, backend and CLI tests, risk-rule tests, sanitization tests, and property-based fuzz tests. CI is configured for Ubuntu, Windows, and macOS, and also runs static analysis, dependency auditing, CodeQL, and package checks. The GitHub-hosted CI workflows still need to run successfully on the published repository; see [docs/REPO_HARDENING.md](docs/REPO_HARDENING.md).

## License

ShadowGuide is distributed under the [MIT License](LICENSE).
