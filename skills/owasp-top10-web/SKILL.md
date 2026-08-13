---
name: owasp-top10-web
description: Use when writing, reviewing, or refactoring web application code — authentication, session/cookie handling, database queries, file access, HTTP request handling, API endpoints, deserialization, dependency management, or server configuration. Invoke for SQL injection, XSS, command injection, access control, IDOR, broken authentication, weak cryptography, insecure deserialization, SSRF, security misconfiguration, outdated/vulnerable dependencies, insufficient logging, and secure-by-design coding practices aligned with the OWASP Top 10 (2021).
license: MIT
metadata:
  domain: security
  version: "1.0.0"
  triggers: OWASP Top 10, SQL injection, XSS, cross-site scripting, access control, IDOR, broken authentication, cryptographic failures, insecure design, security misconfiguration, vulnerable components, SSRF, server-side request forgery, insecure deserialization, security logging, session management, password hashing, secure coding, web application security
  role: specialist
  scope: code-generation-and-review
  output-format: guidance-and-code
  related-skills: owasp-api-security, owasp-asvs-secure-coding, owasp-dependency-secrets, owasp-llm-security
---

# OWASP Top 10 Web Application Security

Applies the OWASP Top 10 (2021) — the industry-standard list of the most
critical web application security risks — as default, always-on guardrails
while writing or reviewing web application code. The goal is to prevent these
risks from being introduced in the first place, not just to flag them after
the fact.

## When to Use This Skill

- Writing or modifying code that touches authentication, sessions, cookies, or tokens
- Building or reviewing database queries, ORM calls, or search/filter endpoints
- Handling file uploads, file paths, or user-supplied filenames
- Building HTTP clients that fetch user-supplied or user-influenced URLs (webhooks, image proxies, link previews, importers)
- Adding or updating third-party dependencies
- Configuring frameworks, servers, headers, CORS, or cloud services
- Implementing deserialization, CI/CD pipelines, or auto-update mechanisms
- Adding logging/monitoring around security-relevant events
- Reviewing a pull request or diff touching any of the above

## Top 10 at a Glance (2021)

| # | Risk | What It Is | Red Flag While Coding |
|---|------|------------|------------------------|
| A01 | Broken Access Control | Users can act outside their intended permissions | Missing/duplicated authorization checks; trusting client-supplied IDs or roles |
| A02 | Cryptographic Failures | Sensitive data exposed due to weak/missing crypto | Plaintext storage, MD5/SHA1 for passwords, hardcoded keys, HTTP instead of HTTPS |
| A03 | Injection | Untrusted input alters a query/command/interpreter | String-concatenated SQL, shell exec with user input, unescaped template output |
| A04 | Insecure Design | Missing security control at the design stage, not just a bug | No rate limiting on sensitive flows, no abuse-case threat modeling, trusting business logic invariants client-side |
| A05 | Security Misconfiguration | Insecure defaults, verbose errors, unnecessary features enabled | Debug mode in production, default credentials, permissive CORS (`*`), directory listing on |
| A06 | Vulnerable and Outdated Components | Using libraries/frameworks with known vulnerabilities | Pinned old versions, no dependency scanning, unmaintained/abandoned packages |
| A07 | Identification and Authentication Failures | Weaknesses in login, session, or credential handling | No brute-force protection, session IDs in URLs, weak password policy, missing MFA option |
| A08 | Software and Data Integrity Failures | Trusting data/code without verifying integrity | Insecure deserialization of untrusted data, unsigned auto-updates, CI/CD without pipeline integrity checks |
| A09 | Security Logging and Monitoring Failures | Attacks go undetected because events aren't logged/alerted | No logs on login failures/access-control denials, secrets logged in plaintext |
| A10 | Server-Side Request Forgery (SSRF) | Server fetches a URL influenced by an attacker | User-supplied URL passed directly to an HTTP client with no allowlist/network restriction |

## Reference Guide

Load the detailed references only when relevant — keep this file as the always-on summary.

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Full checklist (detect/insecure/secure/fix per category) | `references/checklist.md` | Reviewing code against A01–A10 in detail, or explaining *why* something is a risk |
| Node.js / TypeScript patterns | `references/stacks/nodejs-typescript.md` | Writing/reviewing Express, NestJS, Fastify, Prisma, pg, mysql2, etc. |
| Python patterns | `references/stacks/python.md` | Writing/reviewing Django, Flask, FastAPI, SQLAlchemy, psycopg2, etc. |
| Java patterns | `references/stacks/java.md` | Writing/reviewing Spring/Spring Security, JPA/Hibernate, JDBC |
| Go patterns | `references/stacks/go.md` | Writing/reviewing net/http, database/sql, gosec-flagged patterns |

## Constraints

### MUST DO

- MUST enforce authorization server-side on every request, defaulting to deny (A01)
- MUST use parameterized queries / prepared statements or a safe ORM API for all data access — never string-concatenated or template-interpolated queries (A03)
- MUST hash passwords with a modern slow hash (bcrypt, scrypt, or Argon2) with a per-user salt (A02, A07)
- MUST validate, sanitize, and/or allowlist all external input, including HTTP client destinations, file paths, and filenames (A03, A10)
- MUST use TLS for data in transit and strong, current algorithms for data at rest (A02)
- MUST keep dependencies inventoried and patched; run automated dependency/vulnerability scanning in CI (A06)
- MUST verify integrity (signatures/checksums) of updates, artifacts, and CI/CD pipeline steps (A08)
- MUST log authentication events, access-control failures, and other security-relevant events with enough context to investigate, and monitor/alert on them (A09)
- MUST restrict, validate, and where possible allowlist destinations for any server-side outbound request built from user input (A10)
- MUST fail securely — deny access and show generic errors on unexpected failures (A04, A05)

### MUST NOT DO

- MUST NOT trust client-supplied object IDs, roles, or flags without a server-side ownership/permission check (A01)
- MUST NOT log secrets, passwords, session tokens, API keys, or full credit-card/PII data (A02, A09)
- MUST NOT build SQL/NoSQL/OS commands via string concatenation or interpolation of untrusted input (A03)
- MUST NOT deserialize untrusted data with unsafe/native deserializers (e.g., Python `pickle`, Java native serialization, PHP `unserialize`) (A08)
- MUST NOT ship debug mode, verbose stack traces, default credentials, or permissive wildcard CORS/CSP to production (A05)
- MUST NOT roll custom cryptography or use deprecated algorithms (MD5, SHA1, DES, ECB mode) for security purposes (A02)
- MUST NOT let a server fetch an arbitrary, unvalidated user-supplied URL, especially to internal/private IP ranges or the cloud metadata endpoint (A10)
- MUST NOT rely on client-side validation alone for security-relevant checks — always re-check server-side (A04)
- MUST NOT add or upgrade a dependency without checking for known vulnerabilities (A06)

## Knowledge Reference

OWASP Top 10 2021, CWE, ASVS, SANS Top 25, CVSS, npm audit / pip-audit / OWASP Dependency-Check, Semgrep, gosec, bandit, SSRF allowlisting, defense-in-depth, least privilege, secure-by-default design.
