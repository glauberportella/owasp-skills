---
name: owasp-asvs-secure-coding
description: Use when implementing authentication, session management, access control, input validation, cryptography, error handling/logging, file upload, or API/webhook features — a prescriptive secure-coding checklist based on OWASP ASVS (Application Security Verification Standard), applied while writing the feature rather than only during audit. Invoke for password storage, JWT/session tokens, MFA, RBAC, output encoding, secrets management, TLS configuration, file upload validation, business logic abuse, and configuration hardening.
license: MIT
metadata:
  domain: security
  version: "1.0.0"
  triggers: OWASP ASVS, secure coding, authentication, session management, access control, RBAC, input validation, output encoding, cryptography, password hashing, JWT, secrets management, error handling, logging, file upload, API security, security configuration, TLS
  role: builder
  scope: implementation
  output-format: checklist
  related-skills: owasp-top10-web, owasp-api-security, owasp-dependency-secrets, owasp-llm-security
---

# OWASP ASVS Secure Coding

Prescriptive, feature-by-feature secure-coding checklist derived from the OWASP Application Security Verification Standard (ASVS). Applied **while building** a feature, not only when auditing it afterward.

## How This Differs From `owasp-top10-web`

- **`owasp-top10-web`** is a **defensive** lens: a list of attack categories (injection, broken access control, XSS, etc.) to recognize and block when reviewing or hardening code.
- **`owasp-asvs-secure-coding`** (this skill) is a **constructive** lens: a positive checklist of controls to build correctly, organized by the feature area you are implementing (login, sessions, access control, crypto, logging, uploads, etc.).

Use this skill when you are writing the feature. Use `owasp-top10-web` when you are reviewing code for known attack patterns. They are complementary siblings in this repo — apply both on security-sensitive work.

## When to Use This Skill

Invoke this skill when implementing:

- **Login / authentication** — password login, MFA/2FA, OAuth/OIDC/SSO, credential recovery, account lockout
- **Sessions** — session cookies, JWT issuance/validation, token refresh/rotation, logout
- **Access control** — RBAC/ABAC, multi-tenant isolation, admin panels, object-level authorization (IDOR prevention)
- **Forms / input handling** — any endpoint accepting user input, file names, search queries, uploaded content
- **Cryptography / secrets** — encrypting data at rest, signing tokens, storing API keys/credentials, key rotation
- **Logging / error handling** — exception handlers, audit trails, request logging, error responses sent to clients
- **File upload** — user-supplied files, avatars, document upload, import pipelines
- **API / webhooks** — REST/GraphQL endpoints, webhook receivers, service-to-service calls, rate limiting
- **Configuration** — environment setup, security headers, CORS, dependency/framework hardening, deployment config

## Skimmable Checklist (ASVS Chapters)

| Chapter | Key requirement while coding |
|---|---|
| V1 Architecture, Design | Threat-model security-sensitive features before coding; define trust boundaries; centralize security controls (auth, validation) rather than duplicating per-endpoint |
| V2 Authentication | Hash passwords with Argon2id/bcrypt; enforce MFA for sensitive actions; rate-limit and lock out after failed attempts; never roll your own auth |
| V3 Session Management | Use framework session tokens or signed JWTs with short expiry; set `Secure`, `HttpOnly`, `SameSite`; rotate session ID on login/privilege change; invalidate on logout |
| V4 Access Control | Enforce authorization server-side on every request; deny by default; check object ownership (no IDOR); never trust client-supplied roles/IDs |
| V5 Validation, Sanitization, Encoding | Validate all input against allow-lists/schemas server-side; use parameterized queries; context-aware output encoding to prevent XSS/injection |
| V6 Cryptography at Rest | Use vetted libraries (libsodium, platform crypto APIs); AES-256-GCM for encryption; never invent your own cipher; manage keys via KMS/vault, not code |
| V7 Error Handling, Logging | Return generic errors to clients; log detailed errors server-side only; never log secrets/PII; log security events (auth failures, access denials) |
| V8 Data Protection | Classify sensitive data; minimize collection/retention; mask/redact in UI and logs; enforce access controls on exports/backups |
| V9 Communications | Enforce TLS 1.2+ everywhere; HSTS; no mixed content; verify certificates on outbound calls; disable weak ciphers/protocols |
| V10 Malicious/Self Code | Verify third-party code/package integrity (checksums, lockfiles, signatures); avoid dynamic code execution (`eval`, dynamic `require`) on untrusted input |
| V11 Business Logic | Enforce workflow state/sequence server-side; validate quantities/prices/limits server-side; prevent replay and race conditions on multi-step flows |
| V12 Files and Resources | Validate file type/size/content server-side; store uploads outside webroot; randomize stored filenames; scan/limit resource consumption (zip bombs, XXE) |
| V13 API and Web Service | Authenticate and authorize every API/webhook call; validate content-type; version APIs; rate-limit; verify webhook signatures |
| V14 Configuration | No debug mode/stack traces in production; secrets via env/vault not source; disable unused features/verbs; set security headers (CSP, X-Frame-Options) |

## Reference Guide

| Topic | Reference | Load When |
|---|---|---|
| Full ASVS Chapter Checklist | `references/checklist.md` | Implementing any feature covered above; need concrete "verify that..." items, common mistakes, and secure-pattern examples per chapter |
| Node.js / TypeScript | `references/stacks/nodejs-typescript.md` | Building in Express/Fastify/NestJS/Next.js — password hashing, session/JWT libs, validation schemas, secrets, TLS, uploads |
| Python | `references/stacks/python.md` | Building in Django/Flask/FastAPI — passlib/argon2-cffi, session/JWT handling, Pydantic validation, secrets, uploads |
| Java | `references/stacks/java.md` | Building in Spring/Spring Boot/Jakarta EE — Spring Security, BCrypt/Argon2, JWT libs, Bean Validation, uploads |
| Go | `references/stacks/go.md` | Building in net/http, Gin, Echo, or similar — golang.org/x/crypto/bcrypt, JWT libs, validation, secrets, uploads |

## Constraints

### MUST DO
- MUST hash passwords with a memory-hard algorithm (Argon2id preferred, or bcrypt with adequate cost factor) — never MD5/SHA1/SHA256 alone
- MUST enforce authorization checks server-side on every request, including checking object ownership (no IDOR)
- MUST validate and sanitize all input server-side, even if also validated client-side
- MUST use parameterized queries / ORM bindings for all database access — never string-concatenated SQL
- MUST invalidate/rotate session identifiers on privilege change (login, password change, logout, MFA enrollment)
- MUST enforce TLS for all network communication, including internal/service-to-service calls
- MUST store secrets (API keys, DB credentials, signing keys) outside source control — env vars, secret manager, or vault
- MUST fail closed on authorization and validation checks (deny by default on error or ambiguity)
- MUST verify webhook/API caller signatures or credentials before processing payloads
- MUST validate uploaded files by content, size, and type, and store them outside the webroot with randomized names

### MUST NOT DO
- MUST NOT roll your own cryptography — use vetted libraries for encryption, hashing, and signing
- MUST NOT include stack traces, internal error details, or debug info in responses sent to clients
- MUST NOT log passwords, tokens, API keys, or other secrets/PII in plaintext
- MUST NOT trust client-supplied role, price, quantity, or ID values without server-side re-validation
- MUST NOT hardcode secrets, credentials, or encryption keys in source code or config committed to version control
- MUST NOT rely on client-side validation or hidden fields/disabled buttons as a security control
- MUST NOT accept unvalidated redirect/forward targets from user input
- MUST NOT disable certificate validation or downgrade TLS for convenience, even in non-production environments
