# ASVS Secure Coding — Go

Concrete implementation guidance for `net/http`, Gin, and Echo services. ASVS chapter IDs are referenced so you can cross-check against `references/checklist.md`.

## Password Hashing (V2 Authentication)

Use `golang.org/x/crypto/bcrypt` (simplest, well-vetted) or `golang.org/x/crypto/argon2` (more tuning control, Argon2id).

```go
import "golang.org/x/crypto/bcrypt"

hash, err := bcrypt.GenerateFromPassword([]byte(password), 12) // cost factor 12+
if err != nil { return err }

err = bcrypt.CompareHashAndPassword(storedHash, []byte(candidatePassword))
if err != nil {
    // invalid credentials — return a generic error, don't distinguish "wrong password" vs "unknown user"
}
```

Argon2id variant if you need more control over memory/time cost:

```go
import "golang.org/x/crypto/argon2"

salt := make([]byte, 16)
rand.Read(salt) // crypto/rand, not math/rand
hash := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
// store salt alongside hash; compare with constant-time byte comparison on verify
```

Never hash passwords with `crypto/sha256` alone — no salt, no work factor.

## Sessions and JWT (V3 Session Management)

**Cookie sessions** with `gorilla/sessions` or a similar store:

```go
store := sessions.NewCookieStore(sessionSecretKey) // 32+ random bytes from crypto/rand
store.Options = &sessions.Options{
    Secure:   true,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode,
    MaxAge:   30 * 60, // 30 min
}

// On login: create a fresh session (don't reuse the pre-auth session ID)
session, _ := store.New(r, "session")
session.Values["userID"] = user.ID
session.Save(r, w)
```

**JWT** using `github.com/golang-jwt/jwt/v5`:

```go
import "github.com/golang-jwt/jwt/v5"

claims := jwt.MapClaims{
    "sub": userID,
    "exp": time.Now().Add(15 * time.Minute).Unix(),
    "iss": "auth-service",
}
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
signed, err := token.SignedString(privateKey)

// Verify: explicitly restrict accepted algorithms via a keyfunc
parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return publicKey, nil
}, jwt.WithValidMethods([]string{"RS256"}))
```

Pitfall: the classic `golang-jwt` vulnerability is trusting `t.Method` without checking it — always validate the algorithm inside the keyfunc (`WithValidMethods` covers this in v5) to prevent algorithm-confusion / `alg: none` attacks.

## Access Control (V4)

Enforce ownership checks in middleware/handlers, not just role checks:

```go
func requireOwnership(loadResource func(id string) (*Document, error)) gin.HandlerFunc {
    return func(c *gin.Context) {
        doc, err := loadResource(c.Param("id"))
        userID := c.MustGet("userID").(string)
        if err != nil || doc == nil || doc.OwnerID != userID {
            c.AbortWithStatus(http.StatusNotFound) // avoid leaking existence via 403
            return
        }
        c.Set("document", doc)
        c.Next()
    }
}

router.GET("/documents/:id", requireAuth, requireOwnership(loadDocument), handler)
```

## Input Validation / Output Encoding (V5)

Use `github.com/go-playground/validator/v10` for struct-tag based validation at the boundary:

```go
type CreateOrderRequest struct {
    ItemID   string `json:"itemId" validate:"required,uuid4"`
    Quantity int    `json:"quantity" validate:"required,gt=0,lte=100"`
}

var req CreateOrderRequest
if err := c.ShouldBindJSON(&req); err != nil { /* 400 */ }
if err := validate.Struct(req); err != nil { /* 400 */ }
```

SQL: always use parameterized queries (`database/sql`, `sqlx`, or an ORM like `gorm` with placeholders) — never `fmt.Sprintf` into SQL:

```go
// BAD
query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)

// GOOD
row := db.QueryRow("SELECT * FROM users WHERE email = $1", email)
```

`html/template` (not `text/template`) auto-escapes output for HTML contexts — always use `html/template` when rendering user data into HTML responses. `text/template` performs no escaping and must never be used for HTML output containing user input.

## Secrets Management (V6, V14)

Load configuration from environment variables via `os.Getenv`, populated by a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault) in deployed environments — never hardcode in source:

```go
dbPassword := os.Getenv("DB_PASSWORD")
if dbPassword == "" {
    log.Fatal("DB_PASSWORD not configured") // fail fast at startup
}
```

Encryption at rest with `crypto/aes` + `crypto/cipher` (AES-GCM):

```go
block, _ := aes.NewCipher(key) // 32-byte key for AES-256
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce) // crypto/rand — unique nonce per encryption call, never reused with the same key
ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
```

Always use `crypto/rand`, never `math/rand`, for any security-sensitive random value (tokens, nonces, IVs, salts).

## TLS / HTTPS Enforcement (V9)

```go
srv := &http.Server{
    Addr:    ":443",
    Handler: router,
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
srv.ListenAndServeTLS(certFile, keyFile)

// Set HSTS via middleware
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
```

For outbound HTTP clients, never set `InsecureSkipVerify: true` in a `tls.Config` used in production — this disables certificate validation entirely and is a frequent source of MITM exposure:

```go
// BAD
http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

// GOOD: rely on default verification, or pin a specific CA if needed
client := &http.Client{Timeout: 10 * time.Second}
```

## Secure File Upload (V12)

```go
import "net/http"

var allowedMime = map[string]bool{"image/png": true, "image/jpeg": true, "application/pdf": true}
const maxUploadSize = 5 << 20 // 5MB

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
    file, _, err := r.FormFile("file")
    if err != nil { http.Error(w, "invalid upload", http.StatusBadRequest); return }
    defer file.Close()

    buf := make([]byte, 512)
    file.Read(buf)
    detectedType := http.DetectContentType(buf) // sniff actual content, not client-declared type
    if !allowedMime[detectedType] {
        http.Error(w, "unsupported file type", http.StatusBadRequest)
        return
    }

    file.Seek(0, io.SeekStart)
    storedName := uuid.New().String()
    dest, _ := os.Create(filepath.Join("/var/app-data/uploads", storedName)) // outside webroot
    defer dest.Close()
    io.Copy(dest, file)
}
```

Never build the destination path from the client-supplied filename (`r.MultipartForm.File[...].Filename`) — it can contain `../` sequences; always generate the stored filename server-side and validate content type by sniffing bytes, not trusting headers.
