# OWASP Top 10 (2021) — Detailed Checklist

Language-agnostic reference for each category: what it is, how to spot it in
code, an insecure example, a secure example, and remediation guidance.
Stack-specific, ecosystem-real snippets live in `references/stacks/*.md`.

---

## A01: Broken Access Control

**What it is:** Restrictions on what authenticated users are allowed to do
are not properly enforced, letting users act outside their intended
permissions (view/edit/delete other users' data, access admin functions,
escalate privileges).

**Detect in code:**
- Endpoints/handlers that fetch a resource by an ID taken from the request without checking it belongs to the current user/tenant
- Authorization logic only in the UI/frontend, absent server-side
- Missing or inconsistent `@RequiresRole`/middleware/guard on sensitive routes
- `grep`-able smells: `findById(req.params.id)` / `.get(id)` immediately followed by a response, with no `.userId ===` / `.ownerId ===` / role check nearby
- CORS configured with `Access-Control-Allow-Origin: *` alongside credentials
- Directory listing enabled, or static file serving without path restriction

**Insecure example:**
```
GET /api/invoices/:id
handler(id):
    invoice = db.findInvoiceById(id)
    return invoice          # no check that invoice.ownerId == currentUser.id
```

**Secure example:**
```
GET /api/invoices/:id
handler(id, currentUser):
    invoice = db.findInvoiceById(id)
    if invoice is null or invoice.ownerId != currentUser.id:
        return 404   # do not leak existence of other users' resources
    return invoice
```

**Remediation:**
- Default deny; require an explicit, server-side check for every access to a resource (ownership, tenant, role)
- Centralize authorization (middleware/guards/policy objects) instead of scattering ad hoc checks
- Use indirect references or re-verify ownership instead of trusting client-supplied IDs (mitigates IDOR)
- Rate-limit and log access-control failures
- Deny by default on CORS; never combine `*` origin with credentialed requests

---

## A02: Cryptographic Failures

**What it is:** Sensitive data (credentials, PII, tokens, payment data) is
exposed or compromised because it wasn't properly encrypted, hashed, or
protected in transit/at rest — or because weak/legacy cryptography was used.

**Detect in code:**
- `md5(`, `sha1(` used for password hashing or token generation
- Hardcoded encryption keys, IVs, or secrets in source
- `http://` URLs for anything handling credentials or sessions
- Custom-rolled encryption/hashing instead of vetted libraries
- Sensitive fields (SSNs, card numbers, tokens) stored in plaintext columns
- Predictable random values (`Math.random()`, `rand()`) used for tokens/session IDs

**Insecure example:**
```
password_hash = md5(password)              # fast, unsalted, broken hash
secret_key = "sk_live_51H8x..."            # hardcoded in source
token = str(random.random())               # predictable session token
```

**Secure example:**
```
password_hash = argon2.hash(password)      # slow, salted, memory-hard
secret_key = os.environ["SECRET_KEY"]      # loaded from secret manager/env
token = secrets.token_urlsafe(32)          # cryptographically secure random
```

**Remediation:**
- Use bcrypt/scrypt/Argon2 for password storage; never a fast general-purpose hash
- Use TLS 1.2+ everywhere; enable HSTS; redirect HTTP to HTTPS
- Store secrets in a secrets manager or environment variables, never in source control
- Use cryptographically secure random generators for tokens, session IDs, and nonces
- Encrypt sensitive data at rest with a vetted algorithm (AES-GCM) and manage keys via KMS
- Classify data and apply the minimum retention/exposure necessary (don't collect/store what you don't need)

---

## A03: Injection

**What it is:** Untrusted input is interpreted as part of a command, query,
or expression by an interpreter (SQL, NoSQL, OS shell, LDAP, template engine),
letting an attacker alter its logic — includes SQL injection, command
injection, and XSS (a special case: HTML/JS injection into a browser).

**Detect in code:**
- String concatenation or f-strings/template literals building a query: `"SELECT ... " + userInput`
- `exec()`, `system()`, `os.system()`, `subprocess.run(..., shell=True)` with any user-influenced argument
- `innerHTML =`, `document.write()`, `dangerouslySetInnerHTML`, or template engines with autoescape disabled, fed with user content
- ORM "raw query" escapes (`.raw()`, `.query()`) used with interpolated strings

**Insecure example:**
```
query = "SELECT * FROM users WHERE name = '" + name + "'"
db.execute(query)

exec("ls " + userInput)

element.innerHTML = userComment
```

**Secure example:**
```
db.execute("SELECT * FROM users WHERE name = ?", [name])   # parameterized

execFile("ls", [userInput])                                  # no shell, args as array

element.textContent = userComment                             # or sanitize with DOMPurify before innerHTML
```

**Remediation:**
- Always use parameterized queries / prepared statements or ORM methods that bind parameters — never build queries via string interpolation
- Avoid shell invocation entirely for user-influenced commands; use argument-array APIs (`execFile`, `subprocess.run([...])`)
- Encode output for its context (HTML entity-encode for HTML, use safe DOM APIs); rely on framework auto-escaping and don't defeat it
- Validate/allowlist input format where possible (e.g., IDs must be numeric) in addition to safe execution APIs
- Use a Content Security Policy as defense in depth against XSS

---

## A04: Insecure Design

**What it is:** A missing or ineffective security control baked into the
design itself — not a coding bug that a patch fixes, but a structural gap
(no threat modeling, no abuse-case analysis, trusting invariants that
attackers can violate).

**Detect in code:**
- Business logic that assumes a client will only ever send "reasonable" values (e.g., negative quantities, price fields sent from client, unbounded loops on user-controlled counts)
- Sensitive flows (password reset, MFA enrollment, checkout) with no rate limiting or step verification
- No separation between trust levels (admin/staff features reachable via the same code path as public features with only a UI toggle)
- Missing anti-automation controls on registration/login (no CAPTCHA/rate limit on brute-forceable flows)

**Insecure example:**
```
checkout(cart, priceFromClient):
    total = priceFromClient        # trusts client-supplied price
    chargeCard(total)
```

**Secure example:**
```
checkout(cart, currentUser):
    total = computeTotalServerSide(cart)   # server is the source of truth for price
    if total <= 0: reject()
    chargeCard(total)
```

**Remediation:**
- Threat-model new features before writing code: enumerate abuse cases, not just happy paths
- Never trust client-supplied values for anything with monetary, permission, or security impact; recompute server-side
- Add rate limiting, throttling, and step-up verification to sensitive flows by design
- Segregate privilege tiers architecturally (separate services/roles), not just via UI conditionals
- Use secure design patterns (allowlists over denylists, fail-closed defaults, least privilege)

---

## A05: Security Misconfiguration

**What it is:** Insecure default settings, incomplete/ad hoc configuration,
open cloud storage, verbose error messages, or unnecessary features/ports/
services left enabled.

**Detect in code/config:**
- `DEBUG = True` / `NODE_ENV` not set to `production` in deployed config
- Default/sample credentials left in config files or documentation
- Stack traces or internal error details returned to clients
- Missing security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS)
- Cloud storage buckets or admin consoles left publicly accessible
- Unused endpoints, sample apps, or admin panels still deployed

**Insecure example:**
```
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });   // leaks internals
});

// settings.py
DEBUG = True
ALLOWED_HOSTS = ["*"]
```

**Secure example:**
```
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// settings.py
DEBUG = False
ALLOWED_HOSTS = ["example.com"]
```

**Remediation:**
- Harden and pin configuration per environment; never deploy debug/dev settings to production
- Return generic error messages to clients; log full details server-side only
- Set security headers by default (e.g., via helmet, Spring Security headers, Django `SecurityMiddleware`)
- Remove unused features, sample code, default accounts, and unnecessary services before deployment
- Automate configuration review (infrastructure-as-code scanning, CIS benchmarks) in CI/CD

---

## A06: Vulnerable and Outdated Components

**What it is:** Using libraries, frameworks, or runtime versions with known
vulnerabilities, or software that is unsupported/unpatched.

**Detect in code:**
- Lockfiles with old/pinned versions and no update process (`package-lock.json`, `requirements.txt`, `go.sum`, `pom.xml`)
- No dependency scanning step in CI (`npm audit`, `pip-audit`, `govulncheck`, OWASP Dependency-Check, Snyk, Dependabot)
- Dependencies pulled from unofficial/untrusted registries or with no integrity checksum
- Frameworks/runtimes past end-of-life (EOL) still in use

**Insecure example:**
```
"dependencies": {
  "lodash": "4.17.4"   // known prototype-pollution CVE, years out of date, no scan in CI
}
```

**Secure example:**
```
"dependencies": {
  "lodash": "^4.17.21"  // patched version
}
// CI: run `npm audit --audit-level=high` and Dependabot/Renovate on a schedule
```

**Remediation:**
- Maintain an inventory of components and versions (SBOM); remove unused dependencies
- Run automated dependency/vulnerability scanning in CI and fail builds on high/critical findings
- Subscribe to security advisories for critical dependencies; patch promptly
- Prefer actively maintained libraries; avoid abandoned packages
- Pin versions with lockfiles and verify integrity (checksums/signatures) on install

---

## A07: Identification and Authentication Failures

**What it is:** Weaknesses in how the application confirms a user's
identity, authenticates sessions, or manages credentials — permitting
credential stuffing, brute force, session hijacking, or session fixation.

**Detect in code:**
- No lockout/rate limiting on login endpoints
- Session IDs passed in URLs (leak via referrer/logs) instead of secure cookies
- Session cookies missing `HttpOnly`, `Secure`, `SameSite` attributes
- No session invalidation on logout or password change
- Weak password policy (no minimum entropy check) or no option for MFA
- Passwords or tokens compared with non-constant-time `==`

**Insecure example:**
```
POST /login
handler(username, password):
    user = db.findUser(username)
    if user.password == password:      # plaintext compare, no rate limit
        response.setCookie("session", user.id)  # predictable, no HttpOnly/Secure
```

**Secure example:**
```
POST /login
handler(username, password):
    checkRateLimit(username, sourceIp)      # throttle brute force
    user = db.findUser(username)
    if user is null or not argon2.verify(user.passwordHash, password):
        return genericAuthError()
    sessionId = secrets.token_urlsafe(32)
    store.createSession(sessionId, user.id, expiresIn=shortLived)
    response.setCookie("session", sessionId, httpOnly=True, secure=True, sameSite="Strict")
```

**Remediation:**
- Rate-limit and lock out (or add increasing delay/CAPTCHA to) repeated failed login attempts
- Store session identifiers only in secure, `HttpOnly`, `SameSite` cookies — never in URLs
- Invalidate/rotate sessions on login, logout, and password/permission changes
- Offer and encourage multi-factor authentication for sensitive accounts
- Enforce reasonable password strength/breach checks server-side; use constant-time comparison for secrets

---

## A08: Software and Data Integrity Failures

**What it is:** Code or data is trusted without verifying its integrity —
insecure deserialization of untrusted data, unsigned software updates, or
CI/CD pipelines without integrity checks, allowing malicious code/data
injection.

**Detect in code:**
- `pickle.loads()`, Java native `ObjectInputStream.readObject()`, PHP `unserialize()`, or similar native deserializers applied to any externally-supplied bytes
- Auto-update or plugin-loading mechanisms that fetch code without signature verification
- CI/CD pipelines that pull dependencies/build steps from unpinned, unverified sources
- Client-side state (e.g., signed JWT `alg: none` acceptance, or trusting a serialized object's embedded class/type)

**Insecure example:**
```
data = pickle.loads(request.body)     # arbitrary code execution if attacker controls body

jwt.decode(token, verify=False)       # trusts token contents without verifying signature
```

**Secure example:**
```
data = json.loads(request.body)       # safe, data-only format
schema.validate(data)

jwt.decode(token, key=publicKey, algorithms=["RS256"])  # verify signature and algorithm explicitly
```

**Remediation:**
- Never deserialize untrusted data with native/binary deserializers; use data-only formats (JSON) with schema validation
- Verify digital signatures/checksums for updates, plugins, and downloaded artifacts before executing them
- Pin and verify build dependencies and CI/CD steps (lockfiles, checksum verification, signed commits/tags)
- Explicitly specify and verify expected algorithms when validating signed tokens (reject `alg: none`, enforce expected algorithm)

---

## A09: Security Logging and Monitoring Failures

**What it is:** Insufficient logging, monitoring, or alerting means breaches
and abuse go undetected, delaying response and increasing damage — or logs
themselves leak sensitive data.

**Detect in code:**
- Authentication failures, access-control denials, and input-validation failures with no corresponding log entry
- Logging that includes passwords, tokens, full card numbers, or other secrets in plaintext
- Logs stored only locally with no aggregation/alerting, or with no tamper protection
- No alerting thresholds for suspicious patterns (repeated 401s/403s, mass data export)

**Insecure example:**
```
logger.info(`User login attempt: ${email} / ${password}`);  // logs secret

// no logging at all on authorization failure:
if (!hasPermission) return res.status(403).end();
```

**Secure example:**
```
logger.info("Login attempt", { email, outcome: "failure", ip: req.ip });  // no password logged

if (!hasPermission) {
  logger.warn("Access denied", { userId, resource, ip: req.ip });
  return res.status(403).end();
}
```

**Remediation:**
- Log all authentication attempts, access-control decisions, and input-validation failures with enough context (who/what/when/from where), never secrets themselves
- Centralize and protect logs (append-only/tamper-evident storage) with retention appropriate to compliance needs
- Set up alerting on abnormal patterns (spike in failed logins, repeated 403s, unexpected admin actions)
- Have and rehearse an incident response plan so detected events lead to timely action

---

## A10: Server-Side Request Forgery (SSRF)

**What it is:** The server fetches a remote resource using a URL that is
fully or partially controlled by an attacker, letting them reach internal
services, cloud metadata endpoints, or otherwise-unreachable hosts through
the server as a proxy.

**Detect in code:**
- HTTP client calls (`fetch`, `axios.get`, `requests.get`, `http.Get`) where the URL/host comes directly from user input (webhooks, "import from URL", link previews, image proxies, PDF generators)
- No allowlist of permitted schemes/hosts before making the outbound request
- No blocking of internal/private IP ranges (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `192.168.0.0/16`) or `file://`/`gopher://` schemes
- Redirects followed without re-validating the final destination

**Insecure example:**
```
POST /fetch-preview
handler(url):
    response = httpClient.get(url)     # attacker can pass http://169.254.169.254/latest/meta-data/
    return response.body
```

**Secure example:**
```
POST /fetch-preview
handler(url):
    parsed = parseUrl(url)
    if parsed.scheme not in ["https"]:
        reject()
    if not isAllowlistedHost(parsed.host) or isPrivateOrLinkLocalIp(resolve(parsed.host)):
        reject()
    response = httpClient.get(url, allowRedirects=False, timeout=shortTimeout)
    return response.body
```

**Remediation:**
- Allowlist permitted destination hosts/schemes for any server-initiated request built from user input; deny by default
- Resolve and block requests to private, loopback, and link-local IP ranges (including cloud metadata IPs) before connecting
- Disable automatic redirect-following, or re-validate the destination after each redirect hop
- Apply network-level segmentation (egress firewall rules) as defense in depth so the application tier cannot reach internal services even if application-level checks are bypassed
- Set short timeouts and response-size limits on outbound requests
