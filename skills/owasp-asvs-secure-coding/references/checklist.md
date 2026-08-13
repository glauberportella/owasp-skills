# OWASP ASVS Secure-Coding Checklist

Practical, developer-facing translation of OWASP ASVS (Application Security Verification Standard) requirements. Each chapter lists concrete "verify that..." items to implement while coding, common mistakes seen in real codebases, and a short secure-pattern example. Language-specific implementation detail lives in `references/stacks/`.

---

## V1 — Architecture, Design and Threat Modeling

**Implement:**
- [ ] Verify that a threat model exists (even informally) for every feature that handles authentication, payments, PII, or admin capability
- [ ] Verify that security controls (authN, authZ, validation, encoding) are implemented once, centrally, and reused — not copy-pasted per endpoint
- [ ] Verify that trust boundaries are explicit: every point where data crosses from client to server, service to service, or user to admin scope is identified and checked
- [ ] Verify that high-risk components (auth, crypto, payment, file handling) are isolated into reviewable modules rather than scattered across the codebase
- [ ] Verify that the architecture defines a default-deny posture: new endpoints/features start locked down and are explicitly opened up, not the reverse

**Common mistakes:**
- Security logic duplicated per-controller, drifting out of sync over time
- No documented trust boundary — client input treated as trusted because "it's validated in the UI"
- Adding a new microservice/endpoint without deciding its authZ model first

**Pattern — centralize instead of duplicate:**
```
// BAD: every route re-implements its own auth check
router.get('/orders/:id', (req, res) => { if (req.user) { ... } })

// GOOD: shared middleware enforces the boundary once
router.get('/orders/:id', requireAuth, requireOwnership('order'), handler)
```

---

## V2 — Authentication

**Implement:**
- [ ] Verify that passwords are hashed with Argon2id (preferred) or bcrypt with a cost factor tuned to ~250ms+ per hash on production hardware
- [ ] Verify that password policies require a minimum length (e.g., 12+ chars) and check against known-breached password lists rather than arbitrary complexity rules
- [ ] Verify that authentication failure messages do not reveal whether the username or password was wrong ("invalid credentials" only)
- [ ] Verify that failed login attempts are rate-limited and accounts are temporarily locked or throttled after repeated failures
- [ ] Verify that multi-factor authentication (TOTP, WebAuthn, or push) is available/enforced for sensitive accounts or actions
- [ ] Verify that credential recovery flows use time-limited, single-use tokens sent out-of-band, and never email the password itself
- [ ] Verify that all authentication decisions are made server-side; no client-side "isLoggedIn" flag is trusted
- [ ] Verify that default/sample credentials are removed before deployment

**Common mistakes:**
- Using SHA-256/MD5 (fast, non-memory-hard) directly on passwords
- Verbose login errors ("user not found" vs "wrong password") enabling enumeration
- No lockout/rate-limit, allowing credential-stuffing and brute force
- Password reset tokens that don't expire or are reusable

**Pattern — password hashing:**
```
// BAD
hash = sha256(password)

// GOOD (Argon2id, illustrative)
hash = argon2id.hash(password, { memoryCost: 19456, timeCost: 2, parallelism: 1 })
```

---

## V3 — Session Management

**Implement:**
- [ ] Verify that session tokens (cookie or JWT) are generated using a cryptographically secure random source with sufficient entropy (128+ bits)
- [ ] Verify that session cookies set `Secure`, `HttpOnly`, and `SameSite=Lax` or `Strict`
- [ ] Verify that a new session identifier is issued on login, and the old one is invalidated (prevents session fixation)
- [ ] Verify that session identifiers are rotated on privilege change (password change, MFA enrollment, role change)
- [ ] Verify that logout invalidates the session/token server-side (not just client-side deletion) where server-side state exists
- [ ] Verify that sessions/JWTs have a bounded absolute lifetime and idle timeout, and that refresh tokens are rotated on use
- [ ] Verify that JWTs are validated for signature, issuer, audience, and expiry on every request — the algorithm is pinned server-side (never trust the `alg` header, reject `none`)

**Common mistakes:**
- JWTs treated as sessions with no revocation mechanism and long/no expiry
- Accepting `alg: none` or allowing algorithm confusion (HS256 vs RS256) in JWT libraries
- Session ID not rotated after login, enabling fixation
- Storing session tokens in `localStorage` (exposed to XSS) instead of `HttpOnly` cookies

**Pattern — JWT verification:**
```
// BAD: trusts whatever alg the token claims
jwt.decode(token)

// GOOD: pin algorithm and verify signature/claims
jwt.verify(token, publicKey, { algorithms: ['RS256'], audience: 'api', issuer: 'auth-service' })
```

---

## V4 — Access Control

**Implement:**
- [ ] Verify that every request enforcing a privileged action re-checks authorization server-side, regardless of what the UI shows
- [ ] Verify that object-level access checks confirm the authenticated user owns/may access the specific resource ID requested (no IDOR)
- [ ] Verify that access control fails closed: on error, missing data, or ambiguous state, the request is denied
- [ ] Verify that role/permission data is read from server-side session/token state, never from a client-supplied field (body, header, or hidden form field)
- [ ] Verify that multi-tenant systems scope every query by tenant ID derived from the authenticated context, not from client input
- [ ] Verify that admin/back-office functionality is protected by the same rigor as customer-facing functionality, not "security by obscurity" (hidden URL)
- [ ] Verify that CORS policy is an explicit allow-list of origins, not `*` combined with credentials

**Common mistakes:**
- Checking role in the frontend only, or trusting a `role` field sent in the request body
- Fetching a resource by ID without checking it belongs to the requesting user/tenant (classic IDOR)
- Admin routes reachable by any authenticated user because the check was "hide the link in the UI"
- `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`

**Pattern — object-level authorization:**
```
// BAD: any authenticated user can read any invoice by ID
const invoice = await Invoice.findById(req.params.id);

// GOOD: scope the query to the authenticated user/tenant
const invoice = await Invoice.findOne({ id: req.params.id, ownerId: req.user.id });
if (!invoice) return res.status(404).end();
```

---

## V5 — Validation, Sanitization and Encoding

**Implement:**
- [ ] Verify that all input from any untrusted source (query, body, headers, cookies, files, third-party APIs) is validated server-side against an explicit schema or allow-list
- [ ] Verify that structured queries (SQL, NoSQL, LDAP, XPath) always use parameterized/prepared statements or ORM bindings — never string concatenation/interpolation of user input
- [ ] Verify that output is encoded for the context it is rendered in (HTML entity encoding, JS string escaping, URL encoding, SQL binding) rather than a single generic "sanitize" pass
- [ ] Verify that HTML rendering of user content goes through an allow-list sanitizer (e.g., DOMPurify) if raw HTML must be supported, and templating auto-escaping is not disabled
- [ ] Verify that file paths derived from user input are canonicalized and checked against an allowed base directory (no path traversal via `../`)
- [ ] Verify that OS command execution avoids shell interpolation — use argument-array APIs, and validate/allow-list any user-influenced arguments
- [ ] Verify that deserialization of untrusted data uses safe formats (JSON) and safe libraries — avoid native object deserialization (e.g., Python `pickle`, Java native serialization, PHP `unserialize`) on untrusted input
- [ ] Verify that XML parsers used on untrusted input have external entity expansion (XXE) disabled

**Common mistakes:**
- Validating only in the client, or validating type but not range/format/length server-side
- Building SQL/NoSQL queries via string interpolation "just this once" for a report or admin tool
- Relying on `innerHTML`/`dangerouslySetInnerHTML` with unsanitized user content
- Using `eval`, `Function()`, or dynamic `require`/`import` on user-influenced strings
- XML parser defaults that resolve external entities, enabling XXE/SSRF

**Pattern — safe query + safe rendering:**
```
// BAD
db.query(`SELECT * FROM users WHERE email = '${email}'`)
el.innerHTML = comment.body

// GOOD
db.query('SELECT * FROM users WHERE email = $1', [email])
el.textContent = comment.body // or DOMPurify.sanitize(comment.body) if HTML is required
```

---

## V6 — Cryptography at Rest

**Implement:**
- [ ] Verify that sensitive data at rest (PII, tokens, financial data) is encrypted using vetted, current algorithms (AES-256-GCM, ChaCha20-Poly1305)
- [ ] Verify that encryption keys are managed by a KMS/vault/HSM, not stored alongside the encrypted data or hardcoded in source
- [ ] Verify that a unique IV/nonce is generated per encryption operation and never reused with the same key
- [ ] Verify that key rotation is supported (versioned keys) so compromise of one key does not require re-encrypting all historical data immediately
- [ ] Verify that random values used for security purposes (tokens, IVs, salts) come from a CSPRNG, never `Math.random()` or equivalent
- [ ] Verify that no custom/home-grown cryptographic algorithm is used anywhere in the codebase

**Common mistakes:**
- Hardcoded encryption keys in source code or config files committed to git
- Reusing IVs across encryption calls with the same key (breaks GCM confidentiality)
- Using `Math.random()` / non-cryptographic RNG to generate tokens or reset codes
- "Encrypting" with XOR or a homegrown cipher instead of a vetted library

**Pattern — authenticated encryption:**
```
// BAD
key = "hardcoded-secret-key-123"
iv = fixedIv

// GOOD
key = kms.getDataKey('customer-pii')  // fetched from KMS/vault at runtime
iv = crypto.randomBytes(12)            // fresh per operation
ciphertext = aesGcmEncrypt(plaintext, key, iv)
```

---

## V7 — Error Handling and Logging

**Implement:**
- [ ] Verify that error responses returned to clients are generic (e.g., "Internal server error") and never include stack traces, SQL errors, or internal paths
- [ ] Verify that detailed error information is logged server-side with enough context (request ID, endpoint, user ID) to diagnose without exposing it externally
- [ ] Verify that security-relevant events (login success/failure, access denials, password changes, admin actions) are logged with timestamp, actor, and outcome
- [ ] Verify that logs never contain plaintext passwords, tokens, API keys, credit card numbers, or other secrets/PII — redact or hash before logging
- [ ] Verify that logging failures (e.g., disk full, log service down) do not crash the application or silently disable security controls
- [ ] Verify that log storage is access-controlled and tamper-resistant enough to support incident investigation

**Common mistakes:**
- Returning `err.stack` or ORM error messages directly in HTTP responses
- Logging full request bodies that include passwords or tokens
- No audit trail for privileged actions, making incident response impossible
- Debug/verbose logging left enabled in production

**Pattern — safe error handling:**
```
// BAD
res.status(500).json({ error: err.stack })

// GOOD
logger.error('order_processing_failed', { requestId, userId, err: err.message, stack: err.stack });
res.status(500).json({ error: 'Internal server error', requestId });
```

---

## V8 — Data Protection

**Implement:**
- [ ] Verify that sensitive data fields are classified (public/internal/confidential/restricted) and handled according to that classification
- [ ] Verify that only the minimum necessary sensitive data is collected and retained (data minimization), with defined retention/deletion policies
- [ ] Verify that sensitive data is masked or truncated in UIs and logs (e.g., show last 4 digits of a card number)
- [ ] Verify that sensitive data is not cached in browser history, URLs, or client-side storage that outlives the session
- [ ] Verify that exports, backups, and admin data-dump tooling enforce the same access controls as the primary application
- [ ] Verify that sensitive data is stripped from client-side error/analytics reporting (e.g., Sentry, analytics SDKs) before it leaves the server

**Common mistakes:**
- Passing sensitive tokens or PII in URL query strings (ends up in logs, browser history, referrer headers)
- Sending full card/SSN data to client-side analytics or crash reporters
- Admin "export to CSV" bypassing row-level authorization checks
- No retention policy — sensitive data kept indefinitely, increasing breach impact

**Pattern — masking sensitive output:**
```
// BAD
res.json({ cardNumber: user.cardNumber })

// GOOD
res.json({ cardNumber: `**** **** **** ${user.cardNumber.slice(-4)}` })
```

---

## V9 — Communications (TLS)

**Implement:**
- [ ] Verify that all client-server and server-server traffic uses TLS 1.2 or higher; plaintext HTTP is redirected or rejected
- [ ] Verify that HSTS (`Strict-Transport-Security`) is set with an appropriate max-age and `includeSubDomains`
- [ ] Verify that certificate validation is enabled on all outbound HTTPS calls made by the application (no `verify=False`/`InsecureSkipVerify`/disabled hostname checks)
- [ ] Verify that weak protocols and ciphers (SSLv3, TLS 1.0/1.1, RC4, export ciphers) are disabled at the server/load balancer
- [ ] Verify that mixed content (HTTP resources loaded from an HTTPS page) does not occur
- [ ] Verify that internal service-to-service calls (microservices, database connections) also use TLS where the network is not fully trusted

**Common mistakes:**
- Disabling TLS certificate verification "temporarily" to fix a local dev issue, then shipping it
- Only terminating TLS at the load balancer and running plaintext HTTP internally on an untrusted network
- Missing HSTS, allowing downgrade attacks via stripped redirects

**Pattern — outbound TLS verification:**
```
// BAD
https.get(url, { rejectUnauthorized: false })

// GOOD
https.get(url) // default verification enabled; never override rejectUnauthorized in production
```

---

## V10 — Malicious/Self Code (Code Integrity)

**Implement:**
- [ ] Verify that dependencies are installed from a lockfile with integrity hashes (`package-lock.json`, `poetry.lock`, `go.sum`) and that CI verifies them
- [ ] Verify that third-party packages are sourced from trusted registries, and unusually-privileged or newly-published packages are reviewed before adoption
- [ ] Verify that the application never executes dynamic code built from untrusted input (`eval`, `exec`, dynamic `require`/`import`, reflection-based invocation)
- [ ] Verify that build/CI pipelines pin action/tool versions by hash or verified tag, not floating `latest` tags, to prevent supply-chain tampering
- [ ] Verify that code-signing or checksum verification is used for any auto-update or plugin-loading mechanism

**Common mistakes:**
- Installing packages without a lockfile, allowing silently different transitive versions across environments
- Using `eval()` to implement a "plugin" or "rules engine" fed by user input
- CI workflow steps pinned to `@main`/`@latest` third-party actions instead of a pinned commit SHA

**Pattern — avoid dynamic execution:**
```
// BAD: user-defined formula executed via eval
result = eval(userFormula)

// GOOD: use a sandboxed expression evaluator with a restricted grammar
result = safeExpressionEvaluator.evaluate(userFormula, allowedFunctions)
```

---

## V11 — Business Logic

**Implement:**
- [ ] Verify that multi-step workflows (checkout, approval chains, onboarding) enforce valid state transitions server-side — a step cannot be skipped or replayed out of order
- [ ] Verify that quantities, prices, discounts, and limits are recalculated/validated server-side, never trusted from client-submitted values
- [ ] Verify that rate limits or cooldowns exist on business actions that can be abused at volume (coupon redemption, voting, referral bonuses, password reset requests)
- [ ] Verify that concurrent requests to the same resource (e.g., double-submitting a payment, redeeming a coupon twice) are protected against race conditions (idempotency keys, DB constraints, locking)
- [ ] Verify that time-based or sequence-based business rules (auction end time, one-per-user limits) cannot be bypassed by manipulating client-sent timestamps or by resubmitting requests

**Common mistakes:**
- Trusting a client-supplied `price` or `discount` field at checkout instead of recomputing server-side
- No idempotency key on payment/order submission, enabling double-charging via retry or double-click
- Workflow state (e.g., "approved") settable directly by the client instead of being derived from server-side transitions
- Coupon/promo code redemption with no per-user/per-code rate limiting, enabling abuse at scale

**Pattern — server-side price recomputation + idempotency:**
```
// BAD
total = req.body.total

// GOOD
total = computeTotal(cartItemsFromDb, discountRulesFromServer)
order = await createOrderIdempotent(idempotencyKey, total)
```

---

## V12 — Files and Resources

**Implement:**
- [ ] Verify that uploaded files are validated by actual content/magic-bytes, not just the client-supplied extension or `Content-Type` header
- [ ] Verify that an allow-list of permitted file types is enforced (reject everything not explicitly allowed), with a maximum file size
- [ ] Verify that uploaded files are stored outside the webroot (or in object storage) and served through a controller that re-checks authorization, never directly executable from the upload directory
- [ ] Verify that stored filenames are randomized/generated server-side — the original client-supplied filename is never used to construct a filesystem path
- [ ] Verify that resource-exhaustion vectors are bounded: request body size limits, upload size limits, decompression ratio limits (zip bombs), and XML entity expansion limits
- [ ] Verify that file processing (image resize, document parsing) that shells out to external tools passes arguments safely and cannot be used for command injection

**Common mistakes:**
- Trusting the `Content-Type` header or file extension alone to decide file type
- Serving `/uploads/<user-supplied-filename>` directly, enabling path traversal or overwrite of existing files
- No upload size limit, enabling denial-of-service via huge file uploads
- Image/PDF processing library invoked via shell command built with string concatenation of the filename

**Pattern — safe upload handling:**
```
// BAD
const filename = req.file.originalname;
fs.writeFileSync(`./public/uploads/${filename}`, req.file.buffer);

// GOOD
const detectedType = await fileTypeFromBuffer(req.file.buffer);
if (!ALLOWED_TYPES.includes(detectedType?.mime)) throw new Error('Unsupported file type');
const storedName = crypto.randomUUID() + detectedType.ext;
await storage.put(`uploads/${storedName}`, req.file.buffer); // storage outside webroot
```

---

## V13 — API and Web Service

**Implement:**
- [ ] Verify that every API endpoint (REST, GraphQL, gRPC) requires authentication unless explicitly designed to be public, and enforces authorization per-operation
- [ ] Verify that request `Content-Type` is validated and unexpected types are rejected, preventing content-type confusion attacks
- [ ] Verify that APIs are versioned and deprecated versions are retired on a defined schedule rather than left running indefinitely
- [ ] Verify that rate limiting and quota enforcement exist per client/API key to prevent abuse and resource exhaustion
- [ ] Verify that GraphQL APIs limit query depth/complexity to prevent denial-of-service via deeply nested queries
- [ ] Verify that webhook receivers validate the sender's signature (HMAC or equivalent) and reject unsigned or replayed payloads (timestamp/nonce check)
- [ ] Verify that CORS and allowed HTTP methods are explicitly scoped per endpoint — unused verbs (`TRACE`, `PUT` where unneeded) are disabled

**Common mistakes:**
- Internal/admin API endpoints left unauthenticated because "no one knows the URL"
- Webhook handlers that trust the payload without verifying an HMAC signature header
- GraphQL schemas with no query depth/complexity limiting, enabling amplification DoS
- No rate limiting, allowing credential stuffing or scraping against public API endpoints

**Pattern — webhook signature verification:**
```
// BAD: process payload with no verification
app.post('/webhook', (req, res) => { handleEvent(req.body); });

// GOOD: verify HMAC signature and timestamp before processing
const expected = hmacSha256(rawBody, webhookSecret);
if (!timingSafeEqual(expected, req.headers['x-signature']) || isStale(req.headers['x-timestamp'])) {
  return res.status(401).end();
}
handleEvent(req.body);
```

---

## V14 — Configuration

**Implement:**
- [ ] Verify that debug mode, verbose error pages, and framework "development" settings are disabled in production
- [ ] Verify that secrets (DB credentials, API keys, signing keys) are supplied via environment variables or a secret manager/vault, never committed to source control
- [ ] Verify that security headers are set: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/frame-ancestors, `Referrer-Policy`
- [ ] Verify that unused HTTP methods, admin interfaces, and default accounts/sample apps are disabled or removed before deployment
- [ ] Verify that dependency and framework versions are current and tracked for known-vulnerability advisories (see `owasp-dependency-secrets` sibling skill)
- [ ] Verify that different environments (dev/staging/prod) use distinct credentials and configuration, with no shared secrets across environments
- [ ] Verify that directory listing is disabled on web servers and error pages do not reveal server/framework version banners

**Common mistakes:**
- `DEBUG=True` (or equivalent) left enabled in a production deployment, leaking stack traces and environment variables
- Secrets committed in `.env` files or config checked into git history
- Missing or overly permissive CSP (`default-src *`) providing no real XSS mitigation
- Same database/API credentials reused across dev, staging, and production

**Pattern — safe configuration loading:**
```
// BAD
const dbPassword = "prod-password-123"; // hardcoded

// GOOD
const dbPassword = process.env.DB_PASSWORD; // injected via secret manager/vault at deploy time
if (!dbPassword) throw new Error('DB_PASSWORD not configured');
```
