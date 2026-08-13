# OWASP API Security Top 10 (2023) — Full Checklist

For each risk: what it is, how to detect it in code/design review, an insecure example, a secure example, and remediation guidance. Pseudo-code is used throughout; see `stacks/*.md` for idiomatic per-language versions.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**What it is:** An endpoint accepts an object identifier (ID, UUID, slug) and returns or mutates that object without verifying the authenticated caller is actually authorized to access *that specific instance*. Authentication succeeds, but authorization for the object is missing or checked incorrectly. This is the API-flavored version of IDOR and is consistently the most exploited API vulnerability class.

**How to detect:**
- Grep for route handlers that take an `:id`/`{id}` path param or body field and pass it straight into a lookup (`findById`, `get_object_or_404`, `SELECT ... WHERE id = ?`) with no `WHERE owner_id = current_user.id` or equivalent clause.
- Ask: "If I change this ID to a value belonging to another tenant/user, does the app 404/403, or does it return data?"
- Check GraphQL resolvers for object-by-ID lookups — the same risk exists per-field, not just per-endpoint.
- Look for authorization checks performed only in the frontend/router (e.g., hiding a link) with no backend enforcement.

**Insecure:**
```
GET /api/invoices/{id}
handler(id):
    invoice = db.find(Invoice, id)      # any authenticated user can pass any id
    return invoice
```

**Secure:**
```
GET /api/invoices/{id}
handler(id, current_user):
    invoice = db.find(Invoice, id)
    if invoice is None or invoice.owner_id != current_user.id:
        return 404   # do not leak existence of other users' objects
    return invoice
```

**Remediation:** Scope every object lookup to the caller (tenant/owner/role) at the data-access layer, not just in a controller-level guard. Prefer query filters (`WHERE owner_id = :uid`) over "fetch then compare in application code," which is easy to forget. Use random, non-sequential, non-guessable IDs (UUIDv4) as defense-in-depth, but never as the sole control. Write an authorization test per endpoint that asserts cross-tenant access is denied.

---

## API2:2023 — Broken Authentication

**What it is:** Weaknesses in how identity is established or verified — weak password/token policies, missing token expiry or revocation, credential stuffing not mitigated, API keys used as the only factor for sensitive operations, or JWTs accepted without full signature/claims validation.

**How to detect:**
- Search for JWT decode calls that skip signature verification (`jwt.decode(token, verify=False)`, `algorithms: ["none"]`), or that don't check `exp`/`aud`/`iss`.
- Check password reset / OTP flows for rate limiting and predictable tokens.
- Look for endpoints reachable with only an API key when they should require full user auth (e.g., a key leaked in a mobile app binary granting admin actions).
- Verify token storage/transmission: tokens in URLs/query strings (logged, cached), long-lived tokens with no refresh/revocation path.
- Check login endpoints for lockout/backoff after repeated failures.

**Insecure:**
```
token = jwt.decode(auth_header, options={"verify_signature": False})
user_id = token["sub"]   # trusts unverified claims
```

**Secure:**
```
token = jwt.decode(auth_header, key=PUBLIC_KEY, algorithms=["RS256"],
                    audience=EXPECTED_AUD, issuer=EXPECTED_ISS)
# jwt library raises on bad signature, expiry, audience, or issuer
user_id = token["sub"]
```

**Remediation:** Always verify signature, expiry, audience, and issuer on tokens; reject `alg: none`. Enforce strong password policy and MFA for sensitive accounts. Rate-limit and lock out authentication endpoints. Use short-lived access tokens with rotating refresh tokens and a revocation mechanism. Never treat a static API key as equivalent to authenticated user identity for privileged actions.

---

## API3:2023 — Broken Object Property Level Authorization

**What it is:** Even when object-level access is correct, individual *properties* of an object may be over-exposed on read (excessive data exposure) or over-writable on create/update (mass assignment). A user might legitimately access their own profile object, but that object still shouldn't expose `passwordHash` or accept a client-supplied `role: "admin"`.

**How to detect:**
- Grep for `Model.create(req.body)`, `Model(**request_data)`, `@RequestBody FullEntity`, or any pattern that binds the entire incoming payload directly to a persistence model.
- Grep for `return jsonify(user.__dict__)`, `res.json(user)` on an ORM instance, or serializers with no explicit field list — anything that dumps a full internal object to the client.
- Check for a `role`, `isAdmin`, `balance`, `verified`, or `price` field on a model that is also accepted from user input on update endpoints.

**Insecure:**
```
POST /api/users/{id}
handler(id, body):
    user = db.find(User, id)
    user.update(**body)     # attacker sends { "role": "admin" } and it's applied
    db.save(user)
    return user              # also leaks passwordHash, internal flags
```

**Secure:**
```
POST /api/users/{id}
handler(id, body: UpdateUserDTO):   # DTO only has name, email — no role/balance
    user = db.find(User, id)
    if user.id != current_user.id: return 403
    user.name = body.name
    user.email = body.email
    db.save(user)
    return UserResponseDTO.from(user)  # explicit allow-listed output fields
```

**Remediation:** Define explicit input DTOs/schemas per endpoint that allow-list writable fields; never bind the full request body to a persistence model. Define explicit output DTOs/serializers that allow-list returned fields; never serialize an ORM entity directly. Treat sensitive fields (`role`, `price`, `balance`, `isVerified`) as server-controlled — set them only from trusted server logic, never from client input.

---

## API4:2023 — Unrestricted Resource Consumption

**What it is:** An endpoint has no limit on how much CPU, memory, bandwidth, storage, or downstream cost a single client or request can consume — enabling denial of service or excessive billing (especially with pay-per-call downstream services like SMS/email/LLM APIs).

**How to detect:**
- Check list/search endpoints for a `limit`/`page_size` parameter with no server-enforced maximum.
- Look for endpoints performing expensive work (image processing, PDF generation, recursive GraphQL queries, N+1 fan-out) with no timeout or concurrency cap.
- Check for missing global/per-user rate limiting middleware.
- Check file upload endpoints for missing max-size limits.
- In GraphQL, check for missing query depth/complexity limits (nested queries can be exponential).

**Insecure:**
```
GET /api/search?limit=100000
handler(limit):
    return db.query(Item).limit(limit).all()   # client controls limit unbounded
```

**Secure:**
```
GET /api/search?limit=50
handler(limit):
    limit = min(limit or 20, 100)   # server-enforced ceiling
    return db.query(Item).limit(limit).all()

# plus global middleware: 100 requests / minute / API key or IP
```

**Remediation:** Enforce server-side maximums for pagination size, request body size, file upload size, and query complexity/depth (GraphQL). Add rate limiting per user/API key/IP at the gateway or middleware layer. Set timeouts on all outbound and expensive operations. Monitor and alert on cost-relevant downstream API usage (SMS, email, LLM tokens).

---

## API5:2023 — Broken Function Level Authorization

**What it is:** The application correctly enforces authentication but fails to verify that the caller's *role or permission level* actually allows the specific function/action being invoked — e.g., a regular user can call an admin-only endpoint because the handler only checks "is logged in," not "is admin." Often arises when admin and regular endpoints share the same router/controller without a re-check.

**How to detect:**
- Grep for admin routes (`/admin/*`, `DeleteUser`, `PromoteUser`, `RefundOrder`) and check whether each handler independently verifies role/permission, rather than relying on route grouping or frontend routing alone.
- Look for HTTP method inconsistencies — e.g., `GET /users/{id}` is protected but `DELETE /users/{id}` on the same resource isn't.
- Check for a single generic "isAuthenticated" middleware used everywhere with no per-route role/permission middleware layered on top.

**Insecure:**
```
DELETE /api/users/{id}
handler(id, current_user):
    # only checks that a valid session/token exists, not the role
    db.delete(User, id)
    return 204
```

**Secure:**
```
DELETE /api/users/{id}
@requires_role("admin")
handler(id, current_user):
    if not current_user.has_role("admin"):
        return 403
    db.delete(User, id)
    return 204
```

**Remediation:** Apply role/permission checks at the handler or route-declaration level for every state-changing or privileged endpoint — never assume grouping under `/admin/` or frontend menu visibility is sufficient. Default-deny: new endpoints should require an explicit permission grant, not inherit broad access. Cover every HTTP verb on a resource, not just the ones exercised by the UI.

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**What it is:** A workflow that is functionally correct and properly authenticated/authorized can still be abused at scale in ways that damage the business — e.g., automated bots buying all limited-stock items (scalping), mass account creation for promo abuse, scraping pricing data, or brute-forcing coupon codes. This risk is about business logic, not a technical bug.

**How to detect:**
- Identify flows with real-world value: purchases, signups, referral/coupon redemption, booking/reservation, review posting.
- Ask: "What happens if this endpoint is called 10,000 times per minute by a script instead of a human?"
- Check for absence of CAPTCHA, device fingerprinting, velocity limits, or human-verification steps on these specific flows (separate from generic rate limiting).
- Check whether the same flow is exposed identically to authenticated and unauthenticated/anonymous traffic without extra friction for anonymous.

**Insecure:**
```
POST /api/coupons/redeem
handler(code, user):
    if db.coupon_valid(code):
        apply_discount(user)   # no limit on attempts, no velocity check
```

**Secure:**
```
POST /api/coupons/redeem
handler(code, user):
    if rate_limiter.exceeded(user.id, "coupon_redeem", max=5, window="1h"):
        return 429
    if suspicious_velocity(user) or fails_captcha(request):
        return 429
    if db.coupon_valid(code):
        apply_discount(user)
```

**Remediation:** Identify business-critical flows explicitly during design and add flow-specific protections: CAPTCHA/human verification, device/behavioral signals, velocity and volume limits distinct from generic API rate limits, and monitoring/alerting tuned to business abuse patterns (not just error rates). Consider requiring stronger identity verification for flows with real monetary value.

---

## API7:2023 — Server Side Request Forgery (SSRF)

**What it is:** The server fetches a remote resource (URL) that is influenced by user input — webhooks, "import from URL," image/link previews, PDF-from-URL — without validating the destination, letting an attacker make the server issue requests to internal services, cloud metadata endpoints, or arbitrary external hosts.

**How to detect:**
- Grep for HTTP client calls (`fetch`, `requests.get`, `http.Get`, `axios.get`, `RestTemplate`) where the URL/host comes from request body, query params, or a webhook config, without validation.
- Check for missing allow-lists on schemes (`http`/`https` only) and hosts.
- Check whether the client follows redirects (a validated URL can redirect to an internal address at request time — TOCTOU).
- Look for cloud metadata endpoints (`169.254.169.254`) or private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`) that aren't explicitly blocked.

**Insecure:**
```
POST /api/import-image
handler(url):
    response = http.get(url)   # attacker sends http://169.254.169.254/latest/meta-data/
    save(response.body)
```

**Secure:**
```
POST /api/import-image
handler(url):
    parsed = parse_url(url)
    if parsed.scheme not in ("http", "https"): return 400
    ip = resolve(parsed.host)
    if is_private_or_link_local(ip) or is_metadata_ip(ip): return 400
    if parsed.host not in ALLOWED_HOSTS: return 400
    response = http.get(url, allow_redirects=False, timeout=3)
    save(response.body)
```

**Remediation:** Validate scheme and resolved IP (not just hostname, to defeat DNS rebinding) against a deny-list of private/link-local/metadata ranges, ideally combined with an allow-list of expected hosts. Disable automatic redirect following, or re-validate the destination after each redirect. Set short timeouts and run outbound fetches from a network-isolated egress path where feasible. Never let user input control internal service URLs directly.

---

## API8:2023 — Security Misconfiguration

**What it is:** Insecure default settings, incomplete or ad-hoc configuration, open cloud storage, verbose error handling, missing security headers, or permissive CORS — issues in how the API and its infrastructure are configured rather than in application logic itself.

**How to detect:**
- Search for `DEBUG = True` / `NODE_ENV !== 'production'` checks left disabled, stack traces returned in error responses.
- Check CORS config for `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
- Check for missing `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security` headers on API responses (where relevant, e.g., for browser-consumed APIs).
- Grep for hardcoded default credentials, unremoved sample/test endpoints, or overly permissive HTTP methods (`TRACE`, `OPTIONS` returning verbose info).
- Check TLS configuration for outdated protocol/cipher support.

**Insecure:**
```
app.use(cors({ origin: "*", credentials: true }))
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack })
})
```

**Secure:**
```
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }))
app.use((err, req, res, next) => {
    log.error(err)   // full detail server-side only
    res.status(500).json({ error: "Internal server error" })
})
```

**Remediation:** Harden configuration as part of the deployment pipeline: disable debug/verbose modes in production, restrict CORS to known origins, return generic error messages to clients while logging full detail server-side, set security headers appropriate to the API's consumers, and remove default accounts/sample endpoints before release. Automate configuration checks (e.g., in CI) rather than relying on manual review per release.

---

## API9:2023 — Improper Inventory Management

**What it is:** Lack of visibility into which API versions, environments, and hosts are actually deployed and reachable, leading to old/undocumented/staging endpoints ("shadow" or "zombie" APIs) that lack current security controls but remain accessible to attackers who find them.

**How to detect:**
- Search infrastructure/routing config for multiple API version prefixes (`/v1/`, `/v2/`, `/internal/`, `/beta/`) and check whether older versions received the same security patches as the current one.
- Check whether staging/QA/internal API hosts are reachable from the public internet.
- Compare deployed routes against the maintained OpenAPI/GraphQL schema — undocumented routes are a red flag.
- Check for API gateway configuration that lists all upstream services — cross-reference against what's actually still needed.

**Insecure:**
```
# v1 kept running "for backwards compatibility" with no auth updates since 2021,
# while v2 got MFA and rate limiting. Both are internet-reachable.
```

**Secure:**
```
# Maintain a single source of truth (OpenAPI/GraphQL schema + gateway config)
# for every deployed version and environment.
# Deprecate v1 on a fixed timeline, or backport the same security controls to it.
# Restrict staging/internal hosts to VPN/allow-listed IPs; never expose them publicly.
```

**Remediation:** Maintain a live, authoritative inventory of every API version, environment, and host (schema registry, API gateway config, or automated discovery). Apply the same authentication, authorization, rate-limiting, and monitoring controls to every reachable version — retire old versions on a schedule rather than leaving them running indefinitely. Restrict non-production environments to trusted networks.

---

## API10:2023 — Unsafe Consumption of APIs

**What it is:** Developers often trust data coming *from* third-party/partner APIs more than data from end users, skipping input validation, size limits, and timeouts on responses — but a compromised or malicious upstream (or a man-in-the-middle) can inject the same classes of attacks (injection, oversized payloads, malicious redirects) through that trusted channel.

**How to detect:**
- Grep for outbound API client calls and check whether the response is validated/schema-checked before use, or deserialized/trusted directly.
- Check whether outbound calls have timeouts and retry/circuit-breaker logic, or can hang indefinitely / retry-storm on a flaky upstream.
- Check whether redirects from third-party APIs are followed blindly.
- Check whether third-party webhook payloads are signature-verified before being processed.
- Check TLS certificate validation isn't disabled for convenience (`verify=False`, `rejectUnauthorized: false`).

**Insecure:**
```
response = requests.get(partner_api_url, timeout=None, verify=False)
data = response.json()
db.save(User(**data))   # trusts and directly persists third-party shape
```

**Secure:**
```
response = requests.get(partner_api_url, timeout=5, verify=True)
response.raise_for_status()
data = PartnerUserSchema.parse(response.json())   # validated, allow-listed shape
db.save(map_to_internal_user(data))
```

**Remediation:** Treat third-party API responses and webhook payloads as untrusted input: validate against a schema, enforce size limits, set timeouts, use circuit breakers for flaky upstreams, verify webhook signatures, and keep TLS certificate validation enabled. Avoid following redirects blindly and avoid deserializing directly into internal persistence models.
