# ASVS Secure Coding — Java

Concrete implementation guidance for Spring Boot / Spring Security and Jakarta EE. ASVS chapter IDs are referenced so you can cross-check against `references/checklist.md`.

## Password Hashing (V2 Authentication)

Spring Security ships `Argon2PasswordEncoder` and `BCryptPasswordEncoder`. Prefer Argon2id; bcrypt (cost 12+) is an acceptable alternative.

```java
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@Bean
public PasswordEncoder passwordEncoder() {
    // memory (KB), iterations, parallelism, hash length, salt length
    return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
}

// Usage
String hash = passwordEncoder.encode(rawPassword);
boolean valid = passwordEncoder.matches(candidatePassword, hash);
```

Never use `MessageDigest.getInstance("SHA-256")` directly on a password — it has no salt or work factor.

## Sessions and JWT (V3 Session Management)

**Spring Session cookies** — configure secure attributes in `application.yml`:

```yaml
server:
  servlet:
    session:
      cookie:
        secure: true
        http-only: true
        same-site: lax
      timeout: 30m
```

Force session ID regeneration on authentication (Spring Security does this by default via `sessionFixation().migrateSession()` in `SessionManagementConfigurer` — verify it is not disabled):

```java
http.sessionManagement(session -> session
    .sessionFixation().migrateSession()
    .maximumSessions(1).expiredUrl("/login?expired")
);
```

**JWT** using `io.jsonwebtoken` (jjwt) or Spring's `NimbusJwtDecoder`:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

String token = Jwts.builder()
    .subject(userId)
    .expiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
    .signWith(privateKey, Jwts.SIG.RS256)   // pin the algorithm explicitly
    .compact();

Jws<Claims> parsed = Jwts.parser()
    .verifyWith(publicKey)
    .requireIssuer("auth-service")
    .build()
    .parseSignedClaims(token);              // throws on invalid signature/expiry
```

Pitfall: never configure a `JwtParser` to accept multiple algorithm families dynamically based on the token header — this enables algorithm-confusion attacks. Pin the expected algorithm/key explicitly per verifier.

## Access Control (V4)

Use method-level security with explicit ownership checks, not just role checks:

```java
@PreAuthorize("hasRole('USER')")
@GetMapping("/documents/{id}")
public DocumentDto getDocument(@PathVariable String id, @AuthenticationPrincipal AppUser user) {
    Document doc = documentRepository.findById(id)
        .filter(d -> d.getOwnerId().equals(user.getId()))
        .orElseThrow(() -> new ResourceNotFoundException()); // 404, don't leak existence
    return toDto(doc);
}
```

Prefer domain-object security expressions (`@PostAuthorize("returnObject.ownerId == authentication.name")`) over ad hoc `if` checks scattered in controllers, and centralize role/permission definitions in `SecurityFilterChain` beans.

## Input Validation / Output Encoding (V5)

Use Jakarta Bean Validation (`javax.validation`/`jakarta.validation`) annotations on DTOs, enforced automatically by Spring MVC with `@Valid`:

```java
public record CreateOrderRequest(
    @NotNull @Pattern(regexp = "^[0-9a-f-]{36}$") String itemId,
    @NotNull @Min(1) @Max(100) Integer quantity
) {}

@PostMapping("/orders")
public OrderDto createOrder(@Valid @RequestBody CreateOrderRequest req) { ... }
```

SQL: use `PreparedStatement`, JPA/Hibernate parameter binding, or Spring Data query methods — never string-concatenate SQL/JPQL:

```java
// BAD
String sql = "SELECT * FROM users WHERE email = '" + email + "'";

// GOOD
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);
```

Thymeleaf and JSP-with-JSTL auto-escape output by default — avoid `th:utext` and raw `<%= %>` scriptlets with user data. If HTML sanitization is required, use OWASP Java HTML Sanitizer.

Disable XXE on XML parsers explicitly (not disabled by default in many JAXP configurations):

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

## Secrets Management (V6, V14)

Use Spring's externalized configuration bound to environment variables or a vault (`spring-cloud-vault`, AWS Secrets Manager) — never hardcode in `application.yml` checked into source control:

```yaml
spring:
  datasource:
    password: ${DB_PASSWORD}   # injected via environment/vault at deploy time
```

Encryption at rest with the JCA (AES/GCM):

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);   // fresh IV per encryption call
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
byte[] ciphertext = cipher.doFinal(plaintext);
```

Never use `Random`/`Math.random()` for security-sensitive values — always `java.security.SecureRandom`.

## TLS / HTTPS Enforcement (V9)

```java
http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
http.headers(headers -> headers.httpStrictTransportSecurity(hsts -> hsts
    .includeSubDomains(true)
    .maxAgeInSeconds(31536000)
));
```

For outbound HTTP clients (`RestTemplate`, `WebClient`, `HttpClient`), never install a custom `TrustManager` that accepts all certificates — that pattern (`X509TrustManager` with empty `checkServerTrusted`) is a common but severe vulnerability; use the JVM default trust store.

## Secure File Upload (V12)

```java
private static final Set<String> ALLOWED_MIME = Set.of("image/png", "image/jpeg", "application/pdf");
private static final long MAX_SIZE = 5 * 1024 * 1024;

@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam MultipartFile file) throws IOException {
    if (file.getSize() > MAX_SIZE) return ResponseEntity.badRequest().body("File too large");

    Tika tika = new Tika();
    String detectedType = tika.detect(file.getBytes()); // sniff actual content, not client-supplied type
    if (!ALLOWED_MIME.contains(detectedType)) {
        return ResponseEntity.badRequest().body("Unsupported file type");
    }

    String storedName = UUID.randomUUID().toString();
    Path target = Paths.get("/var/app-data/uploads").resolve(storedName); // outside webroot
    Files.write(target, file.getBytes());
    return ResponseEntity.ok(Map.of("id", storedName));
}
```

Never use `file.getOriginalFilename()` to construct the storage path — it is attacker-controlled and enables path traversal; always generate the filename server-side and validate content via magic-byte detection (e.g., Apache Tika), not the declared `Content-Type`.
