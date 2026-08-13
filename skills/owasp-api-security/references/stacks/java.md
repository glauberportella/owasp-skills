# Java — OWASP API Security Patterns

Covers Spring Boot / Spring Security (method security, `@PreAuthorize`), Bucket4j for rate limiting, and DTO mapping. IDs reference `references/checklist.md` (API1-API10).

## BOLA — Object-Level Authorization (API1)

```java
// INSECURE — fetches by ID with no ownership check
@GetMapping("/invoices/{id}")
public InvoiceDto getInvoice(@PathVariable Long id) {
    return invoiceRepository.findById(id)
        .map(InvoiceDto::from)
        .orElseThrow(() -> new NotFoundException());
}

// SECURE — repository query scoped to the authenticated user
@GetMapping("/invoices/{id}")
public InvoiceDto getInvoice(@PathVariable Long id, @AuthenticationPrincipal UserDetails principal) {
    Invoice invoice = invoiceRepository
        .findByIdAndOwnerId(id, currentUserId(principal))
        .orElseThrow(NotFoundException::new); // 404, don't leak existence
    return InvoiceDto.from(invoice);
}
```

```java
// SECURE — Spring Security @PreAuthorize with a custom permission evaluator
@PreAuthorize("@invoiceSecurity.isOwner(#id, principal)")
@GetMapping("/invoices/{id}")
public InvoiceDto getInvoice(@PathVariable Long id) {
    return InvoiceDto.from(invoiceRepository.findById(id).orElseThrow());
}

@Component("invoiceSecurity")
public class InvoiceSecurity {
    public boolean isOwner(Long invoiceId, UserPrincipal principal) {
        return invoiceRepository.findById(invoiceId)
            .map(i -> i.getOwnerId().equals(principal.getId()))
            .orElse(false);
    }
}
```

## Broken Function-Level Authorization (API5)

```java
// INSECURE — only @Authenticated (implicit), no role check
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id);
}

// SECURE — method-level security enforces role at the handler
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id);
}
```

```java
// Enable method security once, globally
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN") // defense-in-depth at gateway too
            .anyRequest().authenticated()
        );
        return http.build();
    }
}
```

## Mass Assignment / Property-Level Authorization (API3)

```java
// INSECURE — binds the request body directly onto the JPA entity
@PatchMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) {
    user.setId(id);
    return userRepository.save(user);   // attacker sends {"role": "ADMIN"}
}

// SECURE — explicit request/response DTOs, mapped field-by-field
public record UpdateUserRequest(
    @NotBlank @Size(max = 100) String name,
    @Email String email
    // role, balance intentionally absent — never bindable from client input
) {}

public record UserResponse(Long id, String name, String email) {
    static UserResponse from(User u) {
        return new UserResponse(u.getId(), u.getName(), u.getEmail());
        // no passwordHash, no role in the output
    }
}

@PatchMapping("/users/{id}")
public UserResponse updateUser(
        @PathVariable Long id,
        @Valid @RequestBody UpdateUserRequest req,
        @AuthenticationPrincipal UserPrincipal principal) {
    if (!id.equals(principal.getId())) throw new ForbiddenException();
    User user = userRepository.findById(id).orElseThrow();
    user.setName(req.name());
    user.setEmail(req.email());
    return UserResponse.from(userRepository.save(user));
}
```

## Rate Limiting / Resource Consumption (API4, API6)

```java
// SECURE — Bucket4j rate limiting filter per API key / IP
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket newBucket() {
        Bandwidth limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String key = req.getHeader("X-API-Key") != null ? req.getHeader("X-API-Key") : req.getRemoteAddr();
        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket());
        if (bucket.tryConsume(1)) {
            chain.doFilter(req, res);
        } else {
            res.setStatus(429);
        }
    }
}
```

```java
// SECURE — server-enforced pagination ceiling
@GetMapping("/search")
public List<ItemDto> search(@RequestParam(defaultValue = "20") int limit,
                             @RequestParam(defaultValue = "0") int offset) {
    int cappedLimit = Math.min(limit, 100); // hard cap regardless of client input
    return itemRepository.findAll(PageRequest.of(offset / cappedLimit, cappedLimit))
        .stream().map(ItemDto::from).toList();
}
```

```java
// SECURE — sensitive business flow (API6): stricter bucket + CAPTCHA on redemption
@PostMapping("/coupons/redeem")
public ResponseEntity<?> redeemCoupon(@RequestBody RedeemRequest req, @AuthenticationPrincipal UserPrincipal principal) {
    Bucket bucket = couponBuckets.computeIfAbsent(principal.getId(),
        k -> Bucket.builder().addLimit(Bandwidth.classic(5, Refill.intervally(5, Duration.ofHours(1)))).build());
    if (!bucket.tryConsume(1)) return ResponseEntity.status(429).build();
    if (!captchaService.verify(req.captchaToken())) return ResponseEntity.badRequest().build();
    // ...redeem logic
    return ResponseEntity.ok().build();
}
```

## SSRF-Safe Outbound Calls (API7)

```java
// INSECURE — fetches whatever URL the client supplies
@PostMapping("/import")
public String importFromUrl(@RequestBody ImportRequest req) {
    return restTemplate.getForObject(req.url(), String.class);
}

// SECURE — validate scheme, resolve + check IP range, allow-list host, no redirects
private static final Set<String> ALLOWED_HOSTS = Set.of("partner-cdn.example.com");

public String safeFetch(String rawUrl) throws Exception {
    URI uri = new URI(rawUrl);
    if (!"https".equals(uri.getScheme())) throw new IllegalArgumentException("Invalid scheme");
    if (!ALLOWED_HOSTS.contains(uri.getHost())) throw new IllegalArgumentException("Host not allowed");

    InetAddress addr = InetAddress.getByName(uri.getHost());
    if (addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
        throw new IllegalArgumentException("Blocked address range");
    }

    HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(3))
        .build();
    HttpRequest request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(3)).build();
    return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
}
```

## Unsafe Consumption of Third-Party APIs (API10)

```java
// INSECURE — trusts and directly persists the partner API response
String json = restTemplate.getForObject(partnerUrl, String.class);
User user = objectMapper.readValue(json, User.class); // maps directly onto entity
userRepository.save(user);

// SECURE — schema-validate via a dedicated DTO, timeout, TLS verification enabled, explicit mapping
public record PartnerUserDto(
    @NotBlank String externalId,
    @Email String email,
    @NotBlank String name
) {}

RestTemplate restTemplate = restTemplateBuilder
    .setConnectTimeout(Duration.ofSeconds(5))
    .setReadTimeout(Duration.ofSeconds(5))
    .build(); // TLS verification stays enabled by default — never disable it

ResponseEntity<PartnerUserDto> response = restTemplate.getForEntity(partnerUrl, PartnerUserDto.class);
PartnerUserDto dto = validator.validate(response.getBody()); // bean validation
userRepository.save(new User(dto.externalId(), dto.email(), dto.name()));
```

## Security Misconfiguration Basics (API8)

```java
// SECURE — generic error handling, no stack traces to the client
@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        log.error("Unhandled exception", ex); // full detail server-side only
        return ResponseEntity.status(500).body(new ErrorResponse("Internal server error"));
    }
}
```

```yaml
# application-prod.yml — production hardening
server:
  error:
    include-message: never
    include-stacktrace: never
springdoc:
  api-docs:
    enabled: false   # disable OpenAPI/Swagger UI in production, or restrict it
```
