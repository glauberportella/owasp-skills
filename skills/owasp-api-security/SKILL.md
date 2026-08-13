---
name: owasp-api-security
description: Use when designing or implementing REST, GraphQL, gRPC, or RPC-style API endpoints — including authorization checks, rate limiting, API gateways, webhooks, and third-party API integrations. Invoke for BOLA/IDOR, broken object-level or function-level authorization, excessive data exposure, mass assignment, resource exhaustion/rate limiting, sensitive business flow abuse (scalping, brute forcing, scraping), SSRF from server-side API calls or webhook callbacks, API security misconfiguration, shadow/zombie API inventory, and unsafe consumption of third-party/upstream APIs. Trigger on API endpoint design/review, adding new routes or controllers, authorization middleware/guards, rate limiter setup, API gateway config, or reviewing OpenAPI/GraphQL schemas for security gaps.
license: MIT
metadata:
  domain: security
  version: "1.0.0"
  triggers: API security, BOLA, IDOR, broken object level authorization, broken authentication, broken function level authorization, mass assignment, excessive data exposure, rate limiting, resource exhaustion, business flow abuse, SSRF, API misconfiguration, API inventory, shadow API, third-party API consumption, OWASP API Top 10
  related-skills: owasp-top10-web, owasp-asvs-secure-coding, owasp-dependency-secrets, owasp-llm-security
---

# OWASP API Security Top 10

Applies the OWASP API Security Top 10 (2023) to API design, implementation, and review. This complements the general OWASP Web Top 10: where the web list emphasizes injection, XSS, and session handling, the API list focuses on **per-endpoint authorization** (does this specific request let the caller touch an object, field, or function it shouldn't?), **business logic abuse** (can the workflow itself be exploited at scale — scalping, credential stuffing, spam?), and **resource consumption** (can a single request or client exhaust CPU, memory, or third-party quota?). Most real-world API breaches are authorization bugs, not crypto or injection bugs — treat every endpoint as a potential access-control decision point.

## When to Use This Skill

- Designing or reviewing REST, GraphQL, gRPC, or RPC endpoints and their authorization model
- Adding new routes, controllers, resolvers, or handlers that accept an object ID, user ID, or resource path
- Writing or reviewing authentication middleware, JWT validation, session/token handling
- Implementing serialization/deserialization of request or response bodies (DTOs, allow-lists, mass assignment risk)
- Setting up rate limiting, pagination, or quota controls on list/search/export endpoints
- Reviewing admin-only or role-gated endpoints for function-level authorization
- Building or reviewing "sensitive business flows" (checkout, signup, coupon redemption, password reset, booking)
- Making outbound HTTP calls from a server based on user-supplied URLs or webhooks (SSRF risk)
- Auditing API inventory (staging/beta/deprecated versions, undocumented endpoints)
- Integrating with or consuming third-party/partner APIs

## Checklist at a Glance

| # | Risk | Red flag while coding an endpoint |
|---|------|------------------------------------|
| API1 | Broken Object Level Authorization (BOLA) | Endpoint fetches/updates an object by ID with no check that the caller owns/can access that specific ID |
| API2 | Broken Authentication | Weak/missing token validation, no expiry check, permissive password reset, API keys treated as sufficient auth |
| API3 | Broken Object Property Level Authorization | Full model/entity serialized to response or bound from request; no per-field allow-list |
| API4 | Unrestricted Resource Consumption | No rate limit, pagination cap, timeout, or payload-size limit on an expensive endpoint |
| API5 | Broken Function Level Authorization | Admin/privileged action reachable by any authenticated user because role/permission isn't re-checked at the handler |
| API6 | Unrestricted Access to Sensitive Business Flows | High-value workflow (purchase, signup, redeem) has no anti-automation control (CAPTCHA, velocity check, device/behavior signal) |
| API7 | Server Side Request Forgery (SSRF) | Server makes an outbound request to a URL/host taken from user input (webhooks, "fetch from URL", image import) without validation |
| API8 | Security Misconfiguration | Verbose errors/stack traces, default creds, permissive CORS, missing security headers, debug mode in production |
| API9 | Improper Inventory Management | Old API versions, staging/internal endpoints, or undocumented routes still reachable without the same controls |
| API10 | Unsafe Consumption of APIs | Third-party API responses trusted/deserialized without validation, redirects followed blindly, no timeout/circuit breaker |

## Reference Guide

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Full API1-API10 checklist (detection, insecure/secure examples, remediation) | `references/checklist.md` | Reviewing or designing any endpoint against the full Top 10 |
| Node.js / TypeScript patterns | `references/stacks/nodejs-typescript.md` | Working in Express, Fastify, or NestJS |
| Python patterns | `references/stacks/python.md` | Working in FastAPI or Django REST Framework |
| Java patterns | `references/stacks/java.md` | Working in Spring Boot / Spring Security |
| Go patterns | `references/stacks/go.md` | Working in a Go HTTP service (net/http, chi, gin, etc.) |

## Constraints

### MUST DO
- MUST verify the requesting user owns/can access the specific object ID on every object-returning or object-mutating endpoint, not just that they're authenticated (API1).
- MUST re-check role/permission at the handler or middleware layer for every privileged action, even if it's only reachable via a "hidden" UI element (API5).
- MUST define an explicit allow-list of fields (DTO/schema) for both request binding and response serialization; never return or bind a raw internal model (API3).
- MUST enforce rate limits, pagination caps, and max payload sizes on list, search, export, and bulk endpoints (API4).
- MUST validate and constrain any server-side outbound request built from user input (scheme, host allow-list, block private/link-local IP ranges, disable redirects to internal targets) (API7).
- MUST apply the same authentication, authorization, and rate-limit controls to every API version and environment that is reachable from the internet, including "internal," "beta," or "deprecated" ones (API9).
- MUST validate, size-limit, and timeout every response from a third-party/upstream API before trusting or persisting it (API10).
- MUST add anti-automation controls (CAPTCHA, velocity/behavioral checks, step-up auth) to business-critical flows that are attractive to bots (signup, checkout, coupon redemption) (API6).

### MUST NOT DO
- MUST NOT trust client-supplied object IDs, tenant IDs, or "isAdmin"-style flags without a server-side ownership/permission check.
- MUST NOT auto-bind full request bodies to ORM/entity models (mass assignment) — always map through an explicit DTO/schema.
- MUST NOT return full internal entities (with password hashes, internal flags, other users' data) and rely on the frontend to hide fields.
- MUST NOT expose stack traces, internal error details, default credentials, or permissive `Access-Control-Allow-Origin: *` with credentials enabled in production.
- MUST NOT leave older API versions or debug/admin endpoints deployed without the current security controls "because nobody uses them."
- MUST NOT make outbound HTTP requests to a URL taken directly from user input without validating and restricting the destination.
