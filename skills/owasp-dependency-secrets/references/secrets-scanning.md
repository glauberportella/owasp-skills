# Secrets Scanning & Prevention

A leaked credential is one of the fastest paths from "public GitHub repo" to
"compromised production system" — bots scan public commits for secrets
within seconds of a push. Prevention (never committing them) matters more
than detection, but both layers are needed: pre-commit hooks catch mistakes
before they leave your machine, CI and platform-level scanning catch what
slips past that.

## gitleaks

Fast, single-binary, regex + entropy-based secret detector. Good default
choice for both local hooks and CI.

```bash
brew install gitleaks   # or: go install github.com/gitleaks/gitleaks/v8@latest

# Scan the working tree
gitleaks detect --source . --verbose

# Scan full git history (not just current files — secrets removed but never rotated still count)
gitleaks detect --source . --log-opts="--all"

# JSON/SARIF report
gitleaks detect --source . -f json -r gitleaks-report.json

# Establish a baseline for pre-existing findings you're tracking separately
gitleaks detect --baseline-path .gitleaks-baseline.json
```

## trufflehog

Detects secrets via regex and entropy, and — for many providers — actively
verifies whether a found credential is still live, which helps prioritize
real incidents over dead test fixtures.

```bash
pip install trufflehog3   # or: brew install trufflehog

trufflehog filesystem .
trufflehog git file://. --since-commit HEAD~200
trufflehog filesystem . --json > trufflehog-report.json
```

## git-secrets

Simple, AWS-credential-focused tool from AWS Labs; good as a lightweight
pre-commit gate if gitleaks/trufflehog feel heavy.

```bash
brew install git-secrets
git secrets --install
git secrets --register-aws
git secrets --scan
git secrets --scan-history
```

## Pre-commit Framework Integration

Use the [pre-commit](https://pre-commit.com/) framework so the scan runs
automatically on every commit, for every contributor, without relying on
memory:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

```bash
pip install pre-commit
pre-commit install          # activates the git hook locally
pre-commit run --all-files  # run once against the whole repo
```

## GitHub Secret Scanning & Push Protection

For repos hosted on GitHub, enable the platform-native layer as well —
it runs server-side, so it protects you even if a contributor skips local
hooks:

- **Secret scanning** (Settings → Code security → Secret scanning): flags
  known credential patterns (cloud provider keys, common SaaS tokens)
  already pushed to the repo, and for public repos is on by default.
- **Push protection**: blocks the push itself when a recognized secret
  pattern is detected, before it ever reaches the remote history.

Enable both for every new repository as part of initial setup, alongside
the pre-commit hook — pre-commit stops most leaks locally, push protection
is the server-side backstop, and secret scanning catches anything that
still gets through (e.g., force-pushes, direct API pushes).

## CI Integration

Run the same scanner again in CI, independent of local hooks — hooks can be
skipped with `--no-verify`, forgotten on a fresh clone, or bypassed
entirely from a web-based commit.

```yaml
# GitHub Actions
- name: Gitleaks
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
# GitLab CI
secret_detection:
  image: zricethezav/gitleaks
  script:
    - gitleaks detect --source . -f sarif -r gl-secret-detection-report.sarif
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.sarif
```

## What To Do When a Secret IS Committed

Treat this as an incident, not a cleanup task. Deleting the file and
committing again is **not** remediation — the secret remains readable in
git history (`git log -p`, any clone, any fork made before the fix) for
anyone who ever pulled the repo, forever.

1. **Rotate the secret immediately** at the provider (AWS, Stripe, GitHub,
   database, etc.) — issue a new key/token and revoke the old one. Do this
   before anything else, even before touching git history.
2. **Assume compromise** — check provider audit logs / billing for unusual
   activity in the exposure window, however short.
3. **Remove it from history** only after rotation, using
   `git filter-repo` (preferred) or BFG Repo-Cleaner:

   ```bash
   # BFG (fast, purpose-built)
   bfg --replace-text secrets-to-remove.txt repo.git

   # git filter-branch (built-in, slower, use if BFG unavailable)
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch path/to/secret-file" \
     --prune-empty --tag-name-filter cat -- --all
   ```

4. **Force-push the rewritten history** and have every collaborator
   re-clone or hard-reset — rewritten history diverges from any existing
   clone/fork.
5. **Notify affected parties** if the secret protected shared or customer
   data (per your incident-response policy).
6. **Add a regression test**: extend the pre-commit/CI scanner's rules or
   baseline so the same pattern is caught next time, and add the exposed
   value's pattern to the scanner config if it's custom (e.g., an internal
   token format).

## Safe Patterns for Secrets in Code

- **Environment variables** — read via `process.env.X` / `os.environ["X"]`
  / `os.Getenv("X")` / `System.getenv("X")`, injected by the platform
  (shell, container orchestrator, CI secret store) at runtime.
- **`.env` files for local development only** — always in `.gitignore`,
  never committed; commit a `.env.example` with placeholder keys and no
  real values so teammates know what to set.
- **Secret managers for anything beyond solo local dev**: AWS Secrets
  Manager, HashiCorp Vault, Google Secret Manager, Azure Key Vault, or
  Doppler — these add access control, audit logging, and rotation that a
  flat env var cannot provide on its own.
- **Never in frontend/client bundles** — anything shipped to a browser,
  mobile app, or desktop client is extractable by any user; API keys with
  real privileges must stay server-side, proxied through your own backend
  if the client needs the capability.
- **Never in logs or error messages** — scrub or redact known secret field
  names (`password`, `token`, `apiKey`, `authorization`) before logging
  request/response bodies or exception details.
- **Least privilege on the secret itself** — scope API keys/tokens to the
  minimum permissions and shortest useful lifetime the provider allows,
  so a future leak is cheaper to contain.

## Common Secret Patterns (for manual grep / custom rules)

| Type | Pattern | Example |
|------|---------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AKIAIOSFODNN7EXAMPLE |
| AWS Secret Key | 40-char base64-ish string | wJalrXUtnFEMI/K7MDENG... |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` | ghp_xxxxxxxxxxxx |
| Slack Token | `xox[baprs]-` | xoxb-xxx-xxx |
| Stripe Key | `sk_live_[A-Za-z0-9]{24}` | sk_live_xxxx |
| Private Key | `-----BEGIN.*PRIVATE KEY-----` | RSA/EC/OpenSSH keys |
| JWT | `eyJ[A-Za-z0-9_-]*\.eyJ` | Encoded tokens (often session, not always secret, but investigate) |

## Quick Reference

| Tool | Best For | Notes |
|------|----------|-------|
| gitleaks | General-purpose, pre-commit + CI | Fast, low false-positive with tuned rules |
| trufflehog | Deep scanning, live-credential verification | Slower, verifies against provider APIs |
| git-secrets | Lightweight, AWS-focused | Good minimal starting point |
| detect-secrets | Baseline-driven, good for legacy repos | Lets you accept pre-existing findings explicitly |
| GitHub secret scanning/push protection | GitHub-hosted repos | Server-side backstop, on by default for public repos |
