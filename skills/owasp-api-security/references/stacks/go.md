# Go — OWASP API Security Patterns

Covers `net/http`-style middleware, `golang.org/x/time/rate`, and explicit struct-based request binding. IDs reference `references/checklist.md` (API1-API10).

## BOLA — Object-Level Authorization (API1)

```go
// INSECURE — fetches by ID with no ownership check
func getInvoice(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    invoice, err := db.FindInvoiceByID(id)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(invoice)
}

// SECURE — query scoped to the authenticated user
func getInvoice(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    userID := currentUserID(r.Context())

    invoice, err := db.FindInvoiceByIDAndOwner(id, userID) // WHERE id=? AND owner_id=?
    if err != nil || invoice == nil {
        http.Error(w, "not found", http.StatusNotFound) // don't leak existence
        return
    }
    json.NewEncoder(w).Encode(invoice)
}
```

## Broken Function-Level Authorization (API5)

```go
// INSECURE — only checks authentication, not role
func deleteUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    db.DeleteUser(id)
    w.WriteHeader(http.StatusNoContent)
}

// SECURE — role-check middleware applied explicitly to the route
func requireRole(role string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := currentUser(r.Context())
            if !user.HasRole(role) {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// router setup
r.With(requireAuth, requireRole("admin")).Delete("/users/{id}", deleteUser)
```

## Mass Assignment / Property-Level Authorization (API3)

```go
// INSECURE — decodes the raw request body into the persistence model
type User struct {
    ID       string `json:"id"`
    Name     string `json:"name"`
    Email    string `json:"email"`
    Role     string `json:"role"`      // attacker sends {"role":"admin"}
    Password string `json:"password"`
}

func updateUser(w http.ResponseWriter, r *http.Request) {
    var user User
    json.NewDecoder(r.Body).Decode(&user) // binds every field, including Role
    db.SaveUser(user)
}

// SECURE — explicit request/response structs; only allow-listed fields are bindable
type UpdateUserRequest struct {
    Name  string `json:"name"`
    Email string `json:"email"`
    // Role, Password intentionally absent — never bindable from client input
}

type UserResponse struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
    // no password hash, no role in the output
}

func updateUser(w http.ResponseWriter, r *http.Request) {
    userID := chi.URLParam(r, "id")
    if userID != currentUserID(r.Context()) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    var req UpdateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil { // e.g. go-playground/validator
        http.Error(w, "invalid input", http.StatusBadRequest)
        return
    }

    user, _ := db.FindUserByID(userID)
    user.Name = req.Name
    user.Email = req.Email
    db.SaveUser(user)

    json.NewEncoder(w).Encode(UserResponse{ID: user.ID, Name: user.Name, Email: user.Email})
}
```

## Rate Limiting / Resource Consumption (API4, API6)

```go
// SECURE — golang.org/x/time/rate per-client token bucket middleware
type limiterStore struct {
    mu       sync.Mutex
    limiters map[string]*rate.Limiter
}

func (s *limiterStore) get(key string) *rate.Limiter {
    s.mu.Lock()
    defer s.mu.Unlock()
    l, ok := s.limiters[key]
    if !ok {
        l = rate.NewLimiter(rate.Every(time.Minute/100), 20) // ~100 req/min, burst 20
        s.limiters[key] = l
    }
    return l
}

func rateLimitMiddleware(store *limiterStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            key := r.Header.Get("X-API-Key")
            if key == "" {
                key = r.RemoteAddr
            }
            if !store.get(key).Allow() {
                http.Error(w, "too many requests", http.StatusTooManyRequests)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

```go
// SECURE — server-enforced pagination ceiling
func search(w http.ResponseWriter, r *http.Request) {
    limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
    if limit <= 0 || limit > 100 {
        limit = 20 // hard cap regardless of client input
    }
    items := db.SearchItems(limit)
    json.NewEncoder(w).Encode(items)
}
```

```go
// SECURE — sensitive business flow (API6): tighter bucket + CAPTCHA on redemption
var couponLimiters = &limiterStore{limiters: map[string]*rate.Limiter{}}

func redeemCoupon(w http.ResponseWriter, r *http.Request) {
    userID := currentUserID(r.Context())
    limiter := couponLimiters.get(userID) // configured for 5/hour in setup
    if !limiter.Allow() {
        http.Error(w, "too many attempts", http.StatusTooManyRequests)
        return
    }
    var req RedeemRequest
    json.NewDecoder(r.Body).Decode(&req)
    if !verifyCaptcha(req.CaptchaToken) {
        http.Error(w, "captcha failed", http.StatusBadRequest)
        return
    }
    // ...redeem logic
}
```

## SSRF-Safe Outbound Calls (API7)

```go
// INSECURE — fetches whatever URL the client supplies
func importFromURL(w http.ResponseWriter, r *http.Request) {
    var req ImportRequest
    json.NewDecoder(r.Body).Decode(&req)
    resp, _ := http.Get(req.URL)
    io.Copy(w, resp.Body)
}

// SECURE — validate scheme, resolve + check IP range, allow-list host, no redirects
var allowedHosts = map[string]bool{"partner-cdn.example.com": true}

func safeFetch(rawURL string) (*http.Response, error) {
    u, err := url.Parse(rawURL)
    if err != nil || u.Scheme != "https" {
        return nil, errors.New("invalid scheme")
    }
    if !allowedHosts[u.Hostname()] {
        return nil, errors.New("host not allowed")
    }

    ips, err := net.LookupIP(u.Hostname())
    if err != nil {
        return nil, err
    }
    for _, ip := range ips {
        if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
            return nil, errors.New("blocked address range")
        }
    }

    client := &http.Client{
        Timeout: 3 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // do not follow redirects
        },
    }
    return client.Get(rawURL)
}
```

## Unsafe Consumption of Third-Party APIs (API10)

```go
// INSECURE — trusts and directly persists the partner API response
resp, _ := http.Get(partnerURL) // no timeout
var user db.User
json.NewDecoder(resp.Body).Decode(&user) // decodes directly into the persistence model
db.SaveUser(user)

// SECURE — dedicated struct for the external shape, timeout, validation, explicit mapping
type PartnerUserResponse struct {
    ExternalID string `json:"externalId" validate:"required"`
    Email      string `json:"email" validate:"required,email"`
    Name       string `json:"name" validate:"required"`
}

client := &http.Client{Timeout: 5 * time.Second} // TLS verification stays enabled by default
resp, err := client.Get(partnerURL)
if err != nil || resp.StatusCode != http.StatusOK {
    return fmt.Errorf("partner API error")
}
defer resp.Body.Close()

var partner PartnerUserResponse
if err := json.NewDecoder(resp.Body).Decode(&partner); err != nil {
    return err
}
if err := validate.Struct(partner); err != nil {
    return err
}
db.SaveUser(db.User{ExternalID: partner.ExternalID, Email: partner.Email, Name: partner.Name})
```

## Security Misconfiguration Basics (API8)

```go
// SECURE — generic error responses, no internals leaked; recover middleware logs full detail
func recoverMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic: %v\n%s", err, debug.Stack()) // full detail server-side only
                http.Error(w, "internal server error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

// SECURE — restrictive CORS instead of a wildcard with credentials
c := cors.New(cors.Options{
    AllowedOrigins:   []string{"https://app.example.com"},
    AllowCredentials: true,
})
```
