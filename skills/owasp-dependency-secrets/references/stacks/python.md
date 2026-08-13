# Python — Dependency & Secrets Hygiene

## Dependency Auditing

```bash
# pip-audit (PyPA-maintained, OSV-backed) — recommended default
pip install pip-audit
pip-audit                          # scans the active environment
pip-audit -r requirements.txt
pip-audit --fix                    # attempt in-place safe upgrades

# safety (broader commercial advisory DB, has a free tier)
pip install safety
safety check
safety check -r requirements.txt --full-report

# poetry projects
poetry export -f requirements.txt --output requirements.txt --without-hashes
pip-audit -r requirements.txt
```

## Pinning & Lockfiles

**requirements.txt + pip-tools (`pip-compile`)**

```bash
pip install pip-tools

# requirements.in holds loose, human-intent constraints
echo "fastapi>=0.110" >> requirements.in

# pip-compile resolves + pins everything, transitive included, with hashes
pip-compile --generate-hashes requirements.in -o requirements.txt

# Install exactly what's pinned, verifying hashes
pip-sync requirements.txt
```

Commit both `requirements.in` (intent) and `requirements.txt` (fully
resolved, hashed lock). Re-run `pip-compile` — don't hand-edit
`requirements.txt`.

**Poetry**

```bash
poetry add requests           # updates pyproject.toml and poetry.lock together
poetry lock --no-update       # regenerate lock without bumping versions
poetry install                # installs exactly what's in poetry.lock
```

Commit `poetry.lock` alongside `pyproject.toml`. Never hand-edit the lock
file; always go through `poetry add`/`poetry update`/`poetry lock`.

**Plain requirements.txt (no lock tool)** — at minimum pin exact versions
(`fastapi==0.110.0`, not `fastapi>=0.110`) so builds are reproducible; this
is a fallback, not a best practice — prefer pip-tools or Poetry.

## Loading Secrets Safely

```python
import os

api_key = os.environ.get("STRIPE_SECRET_KEY")
if not api_key:
    raise RuntimeError("STRIPE_SECRET_KEY is not set")
```

```python
# python-dotenv — local development convenience only
from dotenv import load_dotenv
load_dotenv()  # reads .env in the working directory; no-op in prod if no .env present

import os
db_url = os.environ["DATABASE_URL"]
```

- `python-dotenv` should only ever load a file that exists locally and is
  git-ignored. In production, set real environment variables via the
  platform (systemd unit, container orchestrator, cloud secret manager) —
  do not package a `.env` file into a deployed image or wheel.
- For Django, keep `SECRET_KEY`, database credentials, and third-party API
  keys out of `settings.py` literals; read them via `os.environ` (often via
  `django-environ` or `python-decouple`) and fail loudly if unset in a
  non-DEBUG environment.
- Never print secrets in `logging` calls or exception messages; scrub known
  sensitive keys before logging a config dict or request payload.
- `.gitignore` must include `.env`, `*.env`, `.env.*` (except
  `.env.example`) before the first commit.

## CI Snippet (GitHub Actions)

```yaml
name: dependency-and-secrets-check

on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: pip-audit (fail on any known vulnerability)
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt

      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
