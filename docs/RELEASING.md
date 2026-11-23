# Releasing

Releases use PyPI Trusted Publishing, so no API token is stored anywhere, and each release carries signed build provenance.

## One-time setup
1. Create the project on PyPI (or use a pending publisher for the first release).
2. In PyPI > Publishing, add a **Trusted Publisher**: your GitHub owner and repository, workflow file `release.yml`, environment `pypi`.
3. In GitHub, create the `pypi` environment with required reviewers (see REPO_HARDENING.md).

## Each release
1. Update `version` in `pyproject.toml` and `__version__` in `src/shadowguide/__init__.py`; add a CHANGELOG entry.
2. Merge to `main` with CI green.
3. Tag and push: `git tag -s v0.3.0 -m "v0.3.0" && git push origin v0.3.0`.
4. The workflow runs the full test and verification suite, builds, attests provenance, then waits for your approval on the `pypi` environment before publishing.

## Verifying a release (for users)
```bash
pip download shadowguide==X.Y.Z --no-deps
gh attestation verify shadowguide-X.Y.Z-py3-none-any.whl --repo OWNER/REPO
```
