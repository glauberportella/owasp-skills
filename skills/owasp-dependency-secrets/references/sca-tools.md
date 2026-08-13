# SCA (Software Composition Analysis) Tools

Software composition analysis tools scan your dependency tree for packages
with known, publicly-disclosed vulnerabilities (CVEs) and, in some cases,
license and provenance issues. They complement SAST — SAST finds bugs in
code you wrote, SCA finds bugs in code you imported.

## npm audit / yarn audit / pnpm audit

**Scans:** the resolved dependency tree in `package-lock.json` /
`yarn.lock` / `pnpm-lock.yaml` against the npm advisory database (and, for
Yarn/pnpm, similar upstream feeds).

```bash
# npm
npm audit
npm audit --omit=dev              # skip devDependencies
npm audit --audit-level=high      # only fail on high/critical
npm audit fix                     # auto-apply safe upgrades
npm audit --json > npm-audit.json

# yarn (classic)
yarn audit
yarn audit --level high

# pnpm
pnpm audit
pnpm audit --prod
```

**Reading output:** each finding lists the vulnerable package, the
vulnerability path (which top-level dependency pulled it in), severity, and
a patched version range. A finding on a *transitive* dependency you don't
control directly may require upgrading the parent package, or using
`overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides` to force a
patched sub-dependency version without waiting on the parent maintainer.

**CI integration:**

```yaml
- name: npm audit
  run: npm audit --audit-level=high
```

Fail the build on `high`/`critical` only in most repos; a full `moderate`
gate on every PR trains teams to ignore the check.

## pip-audit / safety (Python)

**pip-audit** (PyPA-maintained) scans installed packages or a requirements
file against the OSV and PyPI advisory databases.

```bash
pip install pip-audit
pip-audit                                  # scans current environment
pip-audit -r requirements.txt
pip-audit --fix                            # attempt safe upgrades
pip-audit -f json -o pip-audit-report.json
```

**safety** (commercial + free tier) checks against the Safety DB / PyUp
advisory feed.

```bash
pip install safety
safety check
safety check -r requirements.txt --full-report
```

Prefer `pip-audit` for a free, open, well-maintained default; add `safety`
if you already pay for its commercial DB for broader coverage.

## OWASP Dependency-Check

Language-agnostic (strong for Java/.NET, also supports Node, Python, Ruby,
Go via plugins), matches dependencies against the NVD (National
Vulnerability Database) using CPE identifiers.

```bash
# CLI
dependency-check --project "my-app" --scan . --format HTML --out ./report

# Maven plugin
mvn org.owasp:dependency-check-maven:check

# Gradle plugin
./gradlew dependencyCheckAnalyze
```

Requires an NVD API key (free) for reasonable update speed of the local
vulnerability database; without one, the first run can be very slow.

## Trivy (filesystem, image, and repo scanning)

Trivy is a fast, single-binary scanner that covers dependency
vulnerabilities, container images, IaC misconfigurations, and secrets in one
tool — useful when you want one command across a polyglot repo.

```bash
brew install trivy   # or: docker run aquasec/trivy

# Scan a project's dependency manifests/lockfiles
trivy fs --scanners vuln .

# Scan a container image
trivy image myapp:latest

# Scan for vulnerabilities + misconfig + secrets in one pass
trivy fs --scanners vuln,secret,misconfig .

# Only fail CI on high/critical
trivy fs --severity HIGH,CRITICAL --exit-code 1 .
```

## Snyk

Commercial SCA/SAST platform with a generous free tier, strong dependency
graph visualization, and auto-fix PRs.

```bash
npm install -g snyk
snyk auth
snyk test                 # dependency vulnerabilities
snyk code test            # SAST
snyk monitor              # continuous monitoring, no local fail
snyk container test myapp:latest
```

## GitHub Dependabot

Not a CLI tool — a GitHub-native background service. Enable via repo
Settings → Security → "Dependabot alerts" and "Dependabot security
updates," or commit a config:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot opens PRs automatically for vulnerable dependencies and can be
combined with any of the CLI tools above as a CI gate on those PRs.

## Triage Policy — Don't Block Every PR on Every Advisory

SCA tools are noisy by default. A sane, sustainable policy:

1. **Gate merges on Critical/High severity only**, for dependencies that are
   actually reachable at runtime (a vulnerable dev-only tool or a build-time
   dependency is lower risk than one in the production request path).
2. **Track Medium/Low findings** in a backlog or dashboard (Dependabot
   alerts, Snyk project view) instead of failing CI — review weekly, not
   per-PR.
3. **Check exploitability, not just CVSS score** — a vulnerability requiring
   local access or a config you never enable may not apply to you. Read the
   advisory, don't just count the number.
4. **No fixed version yet?** Add a documented, time-boxed suppression
   (e.g., an `.nsprc`/ignore rule with a comment and a follow-up ticket) —
   never a silent, permanent ignore.
5. **Re-run the scan on every dependency change**, not just on a schedule —
   the moment of adding/upgrading a dependency is the cheapest time to catch
   a problem, before it's woven into the codebase.
6. **Distinguish direct vs. transitive** — prioritize upgrading the direct
   dependency; if the vulnerability is several levels deep, an override/
   resolution pin is often faster than waiting for every maintainer in the
   chain to release a patch.

## Quick Reference

| Tool | Ecosystem | Best For |
|------|-----------|----------|
| npm/yarn/pnpm audit | Node.js | Built-in, zero-setup, fast |
| pip-audit | Python | PyPA-official, OSV-backed |
| safety | Python | Broader commercial advisory DB |
| OWASP Dependency-Check | Java/.NET (+plugins) | NVD-backed, CI/build-tool native |
| Trivy | Any (fs/image/IaC/secrets) | One tool, polyglot, containers |
| Snyk | Any (commercial) | Auto-fix PRs, dependency graphs |
| Dependabot | Any (GitHub-native) | Passive monitoring + auto-PRs |
