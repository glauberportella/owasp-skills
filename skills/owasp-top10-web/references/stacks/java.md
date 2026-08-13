# OWASP Top 10 — Java Patterns

Idiomatic secure vs. insecure snippets for a typical Java stack
(Spring Boot, Spring Security, JPA/Hibernate, JDBC/PreparedStatement).

## A01: Broken Access Control

```java
// INSECURE — no ownership check, trusts the path variable
@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}

// SECURE — verify ownership server-side, default deny
@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable Long id, @AuthenticationPrincipal User currentUser) {
    Document doc = documentRepository.findByIdAndOwnerId(id, currentUser.getId())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return doc;
}
```

```java
// SECURE — centralize method-level authorization with Spring Security
@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id) { /* ... */ }
```

## A02: Cryptographic Failures

```java
// INSECURE — MD5 for password hashing, hardcoded secret
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());
String jwtSecret = "hardcoded-secret-key";

// SECURE — BCryptPasswordEncoder for passwords, secret from config/secret manager
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}

String hashed = passwordEncoder.encode(rawPassword);
boolean matches = passwordEncoder.matches(rawPassword, hashed);

@Value("${jwt.secret}")   // sourced from environment/secret manager, not hardcoded
private String jwtSecret;
```

```java
// SECURE — Spring Security: enforce HTTPS and HSTS
http
    .requiresChannel(channel -> channel.anyRequest().requiresSecure())
    .headers(headers -> headers.httpStrictTransportSecurity(
        hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(63072000)));
```

## A03: Injection (SQL / Command)

```java
// INSECURE — string-concatenated SQL
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// SECURE — PreparedStatement with bound parameters
String sql = "SELECT * FROM users WHERE email = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, email);
ResultSet rs = stmt.executeQuery();

// SECURE — JPA/Hibernate with named parameters (never string-build JPQL from input)
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);
```

```java
// INSECURE — command injection via Runtime.exec with a shell-built string
Runtime.getRuntime().exec("convert " + filename + " output.png");

// SECURE — no shell, arguments as an array via ProcessBuilder
new ProcessBuilder("convert", filename, "output.png").start();
```

## A04: Insecure Design

```java
// INSECURE — trusts a client-supplied total at checkout
@PostMapping("/checkout")
public void checkout(@RequestBody CheckoutRequest req) {
    chargeCard(req.getUserId(), req.getTotal()); // total supplied by client
}

// SECURE — recompute price server-side; throttle sensitive endpoints
@PostMapping("/checkout")
@RateLimiter(name = "checkout") // e.g. via resilience4j
public void checkout(@RequestBody CheckoutRequest req, @AuthenticationPrincipal User user) {
    BigDecimal total = pricingService.computeTotal(req.getCartItems()); // server is source of truth
    if (total.compareTo(BigDecimal.ZERO) <= 0) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    chargeCard(user.getId(), total);
}
```

## A05: Security Misconfiguration

```java
// INSECURE — leaks stack traces to clients, permissive CORS
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handle(Exception e) {
    return ResponseEntity.status(500).body(ExceptionUtils.getStackTrace(e));
}

@CrossOrigin(origins = "*")  // combined with credentials, this is dangerous
```

```java
// SECURE — generic error response, log server-side, restrictive CORS
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handle(Exception e) {
    log.error("Unhandled exception", e);
    return ResponseEntity.status(500).body("Internal server error");
}

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://app.example.com"));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

```properties
# INSECURE application.properties — actuator endpoints wide open, debug info exposed
management.endpoints.web.exposure.include=*
spring.jpa.show-sql=true

# SECURE — restrict actuator exposure, disable in production
management.endpoints.web.exposure.include=health,info
spring.jpa.show-sql=false
```

## A06: Vulnerable and Outdated Components

```xml
<!-- Run in CI: OWASP Dependency-Check Maven plugin -->
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.2.0</version>
  <executions>
    <execution>
      <goals><goal>check</goal></goals>
    </execution>
  </executions>
</plugin>
```

```xml
<!-- INSECURE — old, vulnerable pinned version -->
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.9.8</version>
</dependency>

<!-- SECURE — patched version, tracked via Dependabot/Renovate -->
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.17.2</version>
</dependency>
```

## A07: Identification and Authentication Failures

```java
// INSECURE — plaintext comparison, no rate limiting, weak session handling
if (user.getPassword().equals(rawPassword)) {
    session.setAttribute("userId", user.getId());
}

// SECURE — BCrypt verify + Spring Security session fixation protection + rate limiting
if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
    // Spring Security's SessionAuthenticationStrategy regenerates the session ID
    // to prevent session fixation
} else {
    throw new BadCredentialsException("Invalid credentials");
}
```

```java
// SECURE — Spring Security session and cookie hardening
http
    .sessionManagement(session -> session
        .sessionFixation(SessionFixationConfigurer::migrateSession)
        .maximumSessions(1))
    .rememberMe(remember -> remember.tokenValiditySeconds(0)); // disable if not needed

server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict
```

## A08: Software and Data Integrity Failures

```java
// INSECURE — native Java deserialization of untrusted data (RCE risk)
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject();

// SECURE — use a data-only format (JSON) with a schema/DTO, never native deserialization
ObjectMapper mapper = new ObjectMapper();
MyDto dto = mapper.readValue(untrustedJson, MyDto.class);
```

```java
// INSECURE — JWT parsed without pinning algorithm or verifying signature
Claims claims = Jwts.parser().parseClaimsJwt(token).getBody(); // unsigned parse

// SECURE — verify signature with an explicit, expected algorithm
Claims claims = Jwts.parserBuilder()
    .setSigningKey(publicKey)
    .build()
    .parseClaimsJws(token)   // requires and verifies signature
    .getBody();
```

## A09: Security Logging and Monitoring Failures

```java
// INSECURE — logs the password, silent on authorization failure
log.info("Login attempt: {} / {}", email, password);
if (!authorized) {
    return ResponseEntity.status(403).build();
}

// SECURE — structured logging without secrets, logs the denial
log.info("Login attempt: email={}, outcome={}, ip={}", email, authorized ? "success" : "failure", request.getRemoteAddr());
if (!authorized) {
    log.warn("Access denied: userId={}, path={}, ip={}", userId, request.getRequestURI(), request.getRemoteAddr());
    return ResponseEntity.status(403).build();
}
```

## A10: Server-Side Request Forgery (SSRF)

```java
// INSECURE — fetches an attacker-controlled URL server-side
@PostMapping("/link-preview")
public String fetchPreview(@RequestBody String url) throws IOException {
    URL target = new URL(url); // could target http://169.254.169.254/latest/meta-data/
    return new String(target.openStream().readAllBytes());
}

// SECURE — allowlist host/scheme, resolve and block private/link-local IPs, no redirects
private static final Set<String> ALLOWLIST = Set.of("example.com", "cdn.example.com");

@PostMapping("/link-preview")
public String fetchPreview(@RequestBody String urlStr) throws IOException {
    URL target = new URL(urlStr);
    if (!"https".equals(target.getProtocol()) || !ALLOWLIST.contains(target.getHost())) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    InetAddress addr = InetAddress.getByName(target.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    HttpURLConnection conn = (HttpURLConnection) target.openConnection();
    conn.setInstanceFollowRedirects(false);
    conn.setConnectTimeout(3000);
    conn.setReadTimeout(3000);
    return new String(conn.getInputStream().readAllBytes());
}
```

## Quick Reference

| Category | Key library/pattern |
|----------|----------------------|
| A01 | Repository queries scoped by owner, `@PreAuthorize` method security |
| A02 | `BCryptPasswordEncoder`, config-sourced secrets, HSTS via Spring Security headers |
| A03 | `PreparedStatement`, JPA named parameters, `ProcessBuilder` over `Runtime.exec` string |
| A04 | Server-side price recomputation, resilience4j `@RateLimiter` on sensitive endpoints |
| A05 | Restricted actuator exposure, generic `@ExceptionHandler`, explicit CORS config |
| A06 | OWASP Dependency-Check Maven/Gradle plugin, Dependabot/Renovate on `pom.xml`/`build.gradle` |
| A07 | `passwordEncoder.matches`, session fixation protection, `cookie.same-site=strict` |
| A08 | Jackson JSON + DTOs instead of `ObjectInputStream`, `Jwts.parserBuilder().setSigningKey(...)` |
| A09 | SLF4J structured logs without secrets, `log.warn` on access denial |
| A10 | Host allowlist, `InetAddress` private/link-local check, `setInstanceFollowRedirects(false)` |
