---
name: owasp-dependency-secrets
description: Use when adding or updating third-party dependencies, setting up CI/CD pipelines, writing code that reads config/credentials, initializing a new repository, or reviewing a pull request that touches package manifests, lockfiles, or .env-like files. Invoke for vulnerable/outdated components, npm audit, yarn audit, pip-audit, safety, OWASP Dependency-Check, Trivy, Snyk, Dependabot, software composition analysis (SCA), supply chain risk, dependency pinning, lockfiles, transitive dependencies, typosquatting, hardcoded secrets, API keys, passwords, tokens, .env files, gitleaks, trufflehog, git-secrets, pre-commit hooks, secret managers, and credential rotation.
license: MIT
metadata:
  domain: security
  version: "1.0.0"
  triggers: dependency vulnerability, vulnerable component, outdated component, npm audit, yarn audit, pip-audit, safety, OWASP Dependency-Check, Trivy, Snyk, Dependabot, software composition analysis, SCA, supply chain security, lockfile, package-lock, poetry.lock, go.sum, typosquatting, hardcoded secret, API key, credential, .env file, gitleaks, trufflehog, git-secrets, secret manager, secret rotation, pre-commit hook
  role: specialist
  scope: code-generation-and-review
  output-format: guidance-and-code
  related-skills: owasp-top10-web, owasp-api-security, owasp-asvs-secure-coding, owasp-llm-security
---

# OWASP Dependency & Secrets Hygiene

Two of the most common real-world causes of breaches are not clever exploits
against custom application logic — they are pulling in a dependency with a
known vulnerability (OWASP Top 10 A06: Vulnerable and Outdated Components)
and accidentally committing a credential to source control. Both are
supply-chain and hygiene problems rather than bugs in code you wrote, which
is why they need their own always-on workflow distinct from the
logic-focused checks in `owasp-top10-web` and `owasp-asvs-secure-coding`.
Attackers actively scan public repos and package registries for both, so the
window between a leak/vulnerability existing and it being exploited can be
minutes, not months.

## When to Use This Skill

- Adding a new dependency (npm/yarn/pnpm, pip/poetry, Maven/Gradle, Go modules, etc.)
- Upgrading or bumping the version of an existing dependency
- Setting up or modifying a CI/CD pipeline
- Writing code that reads configuration, API keys, tokens, or credentials
- Reviewing a pull request that touches package manifests, lockfiles, or `.env`-like files
- Initializing a new repository or service

## Dependency Hygiene Checklist

- [ ] Pin dependency versions and commit the lockfile (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `go.sum`, etc.)
- [ ] Review a new dependency before adding it: maintenance status, download counts, open issues/CVEs, license
- [ ] Run an SCA/vulnerability scan (`npm audit`, `pip-audit`, `OWASP Dependency-Check`, `Trivy`, `Snyk`) before merging any change that adds or upgrades a dependency
- [ ] Monitor advisories continuously (Dependabot, Snyk, GitHub security alerts) rather than only at add-time
- [ ] Minimize dependency count and transitive surface — prefer a small well-maintained library or a few lines of your own code over a heavy package for a trivial task
- [ ] Verify package provenance/name before installing — watch for typosquatting (`lodahs`, `reqeusts`) and newly-published or low-download packages impersonating popular ones
- [ ] Check the changelog/release notes before a major-version upgrade, not just that the tests pass

## Secrets Hygiene Checklist

- [ ] Never hardcode API keys, passwords, tokens, or connection strings in source code or config files that get committed
- [ ] Load secrets from environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault, Doppler, GCP Secret Manager) — never from a file checked into git
- [ ] Add `.env` and other local secret files to `.gitignore`; commit only `.env.example` with placeholder values
- [ ] Run a secrets scanner pre-commit (gitleaks, trufflehog, git-secrets) and again in CI as a second line of defense
- [ ] Rotate any secret immediately if it is ever exposed — committed, logged, pasted, or shared — and treat it as compromised even after deletion
- [ ] Never write secrets to logs, error messages, stack traces, or telemetry
- [ ] Never embed secrets in client-side/frontend code or mobile app bundles — anything shipped to a browser or device is public

## Reference Guide

Load the detailed references only when relevant — keep this file as the always-on summary.

| Topic | Reference | Load When |
|-------|-----------|-----------|
| SCA tools (npm/yarn audit, pip-audit, safety, Dependency-Check, Trivy, Snyk, Dependabot) | `references/sca-tools.md` | Choosing/running a dependency scanner, triaging scan output, wiring SCA into CI |
| Secrets scanning & prevention (gitleaks, trufflehog, git-secrets, pre-commit, GitHub push protection) | `references/secrets-scanning.md` | Setting up secret scanning, handling a leaked secret, choosing a secret manager |
| Node.js / TypeScript | `references/stacks/nodejs-typescript.md` | npm/yarn/pnpm audit, lockfiles, dotenv, CI snippets for Node projects |
| Python | `references/stacks/python.md` | pip-audit/safety, requirements.txt + pip-compile, poetry.lock, CI snippets for Python projects |
| Java | `references/stacks/java.md` | OWASP Dependency-Check, Maven/Gradle dependency locking, CI snippets for Java projects |
| Go | `references/stacks/go.md` | govulncheck, go.sum verification, CI snippets for Go projects |

## Constraints

### MUST DO

- MUST run a dependency vulnerability scan before merging any change that adds or upgrades a dependency
- MUST use a lockfile and commit it to version control
- MUST load secrets from environment variables or a secret manager, never from a hardcoded literal
- MUST add a secrets-scanning pre-commit hook and a corresponding CI check to new repositories
- MUST rotate a secret immediately once it has been exposed, even if the commit is later removed or force-pushed away
- MUST check the changelog and advisories before a major-version dependency upgrade
- MUST add `.env` and other local secret files to `.gitignore` before the first commit of a new repo

### MUST NOT DO

- MUST NOT hardcode API keys, passwords, or tokens in source code, config files committed to git, or client-side/frontend code
- MUST NOT silently upgrade a dependency across a major version without checking its changelog/advisories first
- MUST NOT treat "delete the file and commit again" as remediation for a leaked secret — git history still contains it
- MUST NOT log secrets, credentials, or full tokens in application logs, error messages, or crash reports
- MUST NOT add a dependency solely because it is convenient without checking its maintenance status and known vulnerabilities
- MUST NOT disable or bypass a secrets-scanning or SCA check in CI to force a merge without an explicit, reviewed exception

## Knowledge Reference

OWASP Top 10 A06 (Vulnerable and Outdated Components), CVE, CVSS, npm audit, yarn audit, pnpm audit, pip-audit, safety, OWASP Dependency-Check, Trivy, Snyk, GitHub Dependabot, gitleaks, trufflehog, git-secrets, pre-commit framework, GitHub secret scanning and push protection, AWS Secrets Manager, HashiCorp Vault, Doppler, GCP Secret Manager, lockfiles, supply chain security, typosquatting.
