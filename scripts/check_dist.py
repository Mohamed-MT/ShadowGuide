"""Verify that the built wheel and sdist contain exactly what they should. Run in CI after `python -m build`."""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

REQUIRED = {"shadowguide/__init__.py", "shadowguide/py.typed", "shadowguide/cli.py", "shadowguide/backends/http.py"}
FORBIDDEN_FRAGMENTS = ("tests/", "conftest", ".github", ".env", ".pyc", "__pycache__", "requirements-dev.lock", ".pem", ".key")
MAX_BYTES = 500_000


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels, sdists = sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))
    problems: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1:
        problems.append(f"expected exactly one wheel and one sdist, found {len(wheels)} and {len(sdists)}")
    for wheel in wheels:
        names = zipfile.ZipFile(wheel).namelist()
        problems += [f"wheel is missing {r}" for r in REQUIRED - set(names)]
        problems += [f"wheel contains forbidden file: {n}" for n in names if any(f in n for f in FORBIDDEN_FRAGMENTS)]
        if not any(n.endswith("licenses/LICENSE") or n.endswith("/LICENSE") for n in names):
            problems.append("wheel does not include the LICENSE file")
        if wheel.stat().st_size > MAX_BYTES:
            problems.append(f"wheel is unexpectedly large ({wheel.stat().st_size} bytes)")
    for sdist in sdists:
        names = tarfile.open(sdist).getnames()
        problems += [f"sdist contains forbidden file: {n}" for n in names if any(f in n for f in (".env", ".pem", ".key", "__pycache__"))]
    for problem in problems:
        print("FAIL:", problem)
    print("dist check:", "FAILED" if problems else "ok", [p.name for p in wheels + sdists])
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
