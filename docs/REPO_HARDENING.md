# Repository hardening checklist (owner actions)

The code and workflows are hardened, but several protections live in your GitHub settings and cannot be set from code. Complete these before the first release.

## Account
- [ ] Two-factor authentication on your GitHub account (use a security key or passkey if you can)
- [ ] Two-factor authentication on your PyPI account
- [ ] Sign commits (SSH or GPG) and require signed commits on `main`

## Repository settings
- [ ] Branch protection on `main`: require pull requests, require the CI jobs (`test`, `quality`, `package`) and CodeQL to pass, require review from Code Owners (see `.github/CODEOWNERS`), block force pushes and deletions
- [ ] Settings > Code security: enable **Private vulnerability reporting**, **Dependabot alerts and security updates**, **Secret scanning and push protection**, and **Code scanning (CodeQL)**
- [ ] Settings > Actions > General: set workflow permissions to **read-only**, and allow only actions owned by GitHub plus the ones you pin (the workflows already pin by SHA)
- [ ] Create an environment named `pypi` with **required reviewers**; releases pause until you approve
- [ ] Tag protection: restrict who can create `v*` tags

## Before each release
- [ ] CI green on Ubuntu, Windows and macOS
- [ ] `docs/AUDIT.md` still accurate; add a CHANGELOG entry
- [ ] Review Dependabot pull requests; regenerate the lock with `uv pip compile pyproject.toml --extra dev --universal --python-version 3.11 --generate-hashes -o requirements-dev.lock`
