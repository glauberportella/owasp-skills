# OWASP Top 10 — Go Patterns

Idiomatic secure vs. insecure snippets for a typical Go stack
(net/http, database/sql, golang.org/x/crypto/bcrypt). Patterns flagged by
`gosec` are called out explicitly.

## A01: Broken Access Control

```go
// INSECURE — no ownership check, trusts the path parameter
func getDocument(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    doc, _ := db.GetDocumentByID(id)
    json.NewEncoder(w).Encode(doc)
}

// SECURE — verify ownership server-side, default deny
func getDocument(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    userID := currentUserID(r.Context())
    doc, err := db.GetDocumentByIDAndOwner(id, userID)
    if err != nil || doc == nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(doc)
}
```

```go
// SECURE — centralize authorization in middleware
func requireOwnership(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !isOwner(r) {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

## A02: Cryptographic Failures

```go
// INSECURE — MD5 for password hashing (gosec: G401/G501), hardcoded secret
import "crypto/md5"
hash := md5.Sum([]byte(password))
var jwtSecret = "hardcoded-secret-key"

// SECURE — bcrypt for passwords, secret from environment/secret manager
import "golang.org/x/crypto/bcrypt"

hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
err = bcrypt.CompareHashAndPassword(hash, []byte(password))

jwtSecret := os.Getenv("JWT_SECRET") // loaded from env/secret manager
```

```go
// INSECURE — TLS verification disabled (gosec: G402)
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

// SECURE — verify certificates, use modern TLS minimum version
tr := &http.Transport{
    TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
}
```

## A03: Injection (SQL / Command)

```go
// INSECURE — string-concatenated SQL (gosec: G201)
query := "SELECT * FROM users WHERE email = '" + email + "'"
rows, err := db.Query(query)

// SECURE — parameterized query via database/sql
rows, err := db.Query("SELECT * FROM users WHERE email = $1", email)

// SECURE — sqlx/ORM with bound parameters
var user User
err := db.Get(&user, "SELECT * FROM users WHERE email = $1", email)
```

```go
// INSECURE — command injection via shell (gosec: G204)
out, err := exec.Command("sh", "-c", "convert "+filename+" output.png").Output()

// SECURE — no shell, arguments passed directly
out, err := exec.Command("convert", filename, "output.png").Output()
```

## A04: Insecure Design

```go
// INSECURE — trusts a client-supplied total at checkout
func checkout(w http.ResponseWriter, r *http.Request) {
    var req CheckoutRequest
    json.NewDecoder(r.Body).Decode(&req)
    chargeCard(req.UserID, req.Total) // total supplied by client
}

// SECURE — recompute price server-side; rate-limit sensitive endpoints
import "golang.org/x/time/rate"

var checkoutLimiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)

func checkout(w http.ResponseWriter, r *http.Request) {
    if !checkoutLimiter.Allow() {
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
    var req CheckoutRequest
    json.NewDecoder(r.Body).Decode(&req)
    total := computeTotalServerSide(req.CartItems) // server is source of truth
    if total <= 0 {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    chargeCard(currentUserID(r.Context()), total)
}
```

## A05: Security Misconfiguration

```go
// INSECURE — leaks internal error details to the client
func errorHandler(w http.ResponseWriter, err error) {
    http.Error(w, err.Error(), http.StatusInternalServerError)
}

// SECURE — generic client-facing error, full detail only in logs
func errorHandler(w http.ResponseWriter, err error) {
    log.Printf("internal error: %v", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
}
```

```go
// INSECURE — permissive CORS, debug pprof exposed in production
w.Header().Set("Access-Control-Allow-Origin", "*")
import _ "net/http/pprof" // mounted on the public router in production

// SECURE — explicit origin allowlist, pprof only behind auth/internal network
w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
// mount pprof on a separate internal-only listener, never the public one
```

## A06: Vulnerable and Outdated Components

```bash
# Run in CI: check Go module dependencies and stdlib for known vulnerabilities
govulncheck ./...

# Keep dependencies patched
go get -u ./...
go mod tidy
```

```go
// go.mod — INSECURE: old, vulnerable pinned version
require golang.org/x/crypto v0.0.0-20200101000000-abcdef123456

// SECURE — patched version, tracked via Dependabot/Renovate
require golang.org/x/crypto v0.26.0
```

## A07: Identification and Authentication Failures

```go
// INSECURE — plaintext comparison, no rate limiting
func login(w http.ResponseWriter, r *http.Request) {
    user := getUserByEmail(r.FormValue("email"))
    if user.Password == r.FormValue("password") {
        setSessionCookie(w, user.ID)
    }
}

// SECURE — bcrypt verify + rate limiting + hardened cookie flags
import "golang.org/x/crypto/bcrypt"

var loginLimiter = rate.NewLimiter(rate.Every(15*time.Minute/10), 10)

func login(w http.ResponseWriter, r *http.Request) {
    if !loginLimiter.Allow() {
        http.Error(w, "too many attempts", http.StatusTooManyRequests)
        return
    }
    user := getUserByEmail(r.FormValue("email"))
    if user == nil || bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(r.FormValue("password"))) != nil {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    sessionID := generateSecureRandomToken(32)
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    sessionID,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    })
}
```

## A08: Software and Data Integrity Failures

```go
// INSECURE — decoding gob/native binary data from an untrusted source (arbitrary type instantiation)
var data any
gob.NewDecoder(untrustedReader).Decode(&data)

// SECURE — use JSON with a fixed struct/schema, never decode into `any` from untrusted input
type Payload struct {
    Name string `json:"name"`
    Age  int    `json:"age"`
}
var p Payload
if err := json.NewDecoder(untrustedReader).Decode(&p); err != nil {
    http.Error(w, "invalid payload", http.StatusBadRequest)
    return
}
```

```go
// INSECURE — JWT parsed without pinning the expected signing method
token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    return publicKey, nil // accepts any algorithm the token claims, including "none"
})

// SECURE — verify the signing method explicitly before trusting claims
token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return publicKey, nil
})
```

## A09: Security Logging and Monitoring Failures

```go
// INSECURE — logs the password, silent on authorization failure
log.Printf("login attempt: %s / %s", email, password)
if !authorized {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}

// SECURE — structured logging without secrets, logs the denial
logger.Info("login attempt", "email", email, "outcome", outcome, "ip", r.RemoteAddr)
if !authorized {
    logger.Warn("access denied", "userID", userID, "path", r.URL.Path, "ip", r.RemoteAddr)
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

## A10: Server-Side Request Forgery (SSRF)

```go
// INSECURE — fetches an attacker-controlled URL server-side (gosec: G107)
func fetchPreview(w http.ResponseWriter, r *http.Request) {
    url := r.FormValue("url")
    resp, _ := http.Get(url) // could target http://169.254.169.254/latest/meta-data/
    io.Copy(w, resp.Body)
}

// SECURE — allowlist host/scheme, block private/link-local IPs, disable redirects, set timeouts
var allowlist = map[string]bool{"example.com": true, "cdn.example.com": true}

func isPrivateOrLinkLocal(host string) bool {
    ips, err := net.LookupIP(host)
    if err != nil {
        return true // fail closed
    }
    for _, ip := range ips {
        if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
            return true
        }
    }
    return false
}

var safeClient = &http.Client{
    Timeout: 3 * time.Second,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse // do not follow redirects automatically
    },
}

func fetchPreview(w http.ResponseWriter, r *http.Request) {
    parsed, err := url.Parse(r.FormValue("url"))
    if err != nil || parsed.Scheme != "https" || !allowlist[parsed.Hostname()] {
        http.Error(w, "invalid url", http.StatusBadRequest)
        return
    }
    if isPrivateOrLinkLocal(parsed.Hostname()) {
        http.Error(w, "invalid url", http.StatusBadRequest)
        return
    }
    resp, err := safeClient.Get(parsed.String())
    if err != nil {
        http.Error(w, "fetch failed", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

## Quick Reference

| Category | Key library/pattern |
|----------|----------------------|
| A01 | Queries scoped by owner ID, authorization middleware, not per-handler checks |
| A02 | `golang.org/x/crypto/bcrypt`, `tls.Config{MinVersion: tls.VersionTLS12}`, env-sourced secrets |
| A03 | `database/sql` placeholders (`$1`/`?`), `exec.Command` without a shell (gosec G201/G204) |
| A04 | Server-side price recomputation, `golang.org/x/time/rate` on sensitive endpoints |
| A05 | Generic error responses, explicit CORS origin, pprof off the public listener |
| A06 | `govulncheck`, Dependabot/Renovate on `go.mod` |
| A07 | `bcrypt.CompareHashAndPassword`, rate limiting on `/login`, `HttpOnly`/`Secure`/`SameSite` cookies |
| A08 | Typed structs with `encoding/json` instead of `gob`/`any`, explicit JWT signing-method check |
| A09 | `log/slog` structured logs without secrets, `logger.Warn` on access denial |
| A10 | Host allowlist, `net.IP.IsPrivate()`/`IsLinkLocalUnicast()`, `CheckRedirect`, client `Timeout` |

## gosec Checks Worth Enabling in CI

```bash
gosec ./...
# Key rules relevant to this skill:
# G201/G202 — SQL string formatting/concatenation (A03)
# G204      — command execution with variable input (A03)
# G107      — potential SSRF via variable URL in HTTP request (A10)
# G401/G501 — weak cryptographic primitive (MD5/DES/etc.) (A02)
# G402      — TLS InsecureSkipVerify or bad min version (A02)
```
