# OWASP Top 10 — Node.js / TypeScript Patterns

Idiomatic secure vs. insecure snippets for a typical Node.js/TypeScript stack
(Express/NestJS/Fastify, pg/mysql2/Prisma, jsonwebtoken, bcrypt/argon2).

## A01: Broken Access Control

```typescript
// INSECURE — trusts the resource ID with no ownership check
app.get('/api/documents/:id', async (req, res) => {
  const doc = await Document.findById(req.params.id);
  res.json(doc);
});

// SECURE — enforce ownership/tenant scoping server-side, default-deny
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await Document.findOne({
    _id: req.params.id,
    ownerId: req.user.id,
  });
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});

// SECURE — NestJS: centralize checks in a guard, not scattered in controllers
@UseGuards(JwtAuthGuard, OwnershipGuard)
@Get('documents/:id')
getDocument(@Param('id') id: string) { /* ... */ }
```

## A02: Cryptographic Failures

```typescript
// INSECURE — fast/broken hash, no salt, secret hardcoded
import crypto from 'crypto';
const hash = crypto.createHash('md5').update(password).digest('hex');
const JWT_SECRET = 'super-secret-key-123';

// SECURE — bcrypt/argon2 for passwords, secret from env/secret manager
import bcrypt from 'bcrypt';
const passwordHash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, passwordHash);

// or argon2 (generally preferred for new systems)
import argon2 from 'argon2';
const passwordHash = await argon2.hash(password);

const JWT_SECRET = process.env.JWT_SECRET; // never hardcoded, loaded from secret store
```

```typescript
// SECURE — enforce HTTPS/HSTS via helmet
import helmet from 'helmet';
app.use(helmet());               // sets sane security headers, incl. HSTS
app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));
```

## A03: Injection (SQL / Command / XSS)

```typescript
// INSECURE — string-concatenated SQL (pg / mysql2)
const result = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);

// SECURE — parameterized query (pg)
const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

// SECURE — parameterized query (mysql2)
const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);

// SECURE — Prisma ORM (parameter binding is automatic)
const user = await prisma.user.findUnique({ where: { email } });
```

```typescript
// INSECURE — shell injection via user input
import { exec } from 'child_process';
exec(`convert ${filename} output.png`);

// SECURE — no shell, arguments passed as an array
import { execFile } from 'child_process';
execFile('convert', [filename, 'output.png']);
```

```typescript
// INSECURE — XSS via unsanitized HTML injection
element.innerHTML = userComment;
// React: return <div dangerouslySetInnerHTML={{ __html: userComment }} />;

// SECURE — rely on safe DOM APIs or React's default escaping
element.textContent = userComment;
return <div>{userComment}</div>;   // React escapes by default

// SECURE — if raw HTML is genuinely required, sanitize first
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userComment);
```

## A04: Insecure Design

```typescript
// INSECURE — trusts client-supplied price at checkout
app.post('/checkout', async (req, res) => {
  const { cartItems, total } = req.body;   // total supplied by client
  await chargeCard(req.user.id, total);
});

// SECURE — recompute price server-side; rate-limit sensitive flows
import rateLimit from 'express-rate-limit';

const checkoutLimiter = rateLimit({ windowMs: 60_000, max: 5 });

app.post('/checkout', checkoutLimiter, requireAuth, async (req, res) => {
  const { cartItems } = req.body;
  const total = await computeTotalServerSide(cartItems); // server is source of truth
  if (total <= 0) return res.status(400).end();
  await chargeCard(req.user.id, total);
});
```

## A05: Security Misconfiguration

```typescript
// INSECURE — leaks stack traces, permissive CORS with credentials
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});
app.use(cors({ origin: '*', credentials: true }));

// SECURE — generic error responses, log details server-side, strict CORS
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal server error' });
});
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use(helmet());
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev')); // verbose logging only outside production
}
```

## A06: Vulnerable and Outdated Components

```bash
# Run in CI, fail the build on high/critical findings
npm audit --audit-level=high
npx better-npm-audit audit

# Keep dependencies current automatically
# .github/dependabot.yml or Renovate configured against package.json
```

```typescript
// INSECURE — pinned to an old, vulnerable version
"dependencies": { "jsonwebtoken": "8.5.1" }

// SECURE — patched version, tracked and updated via Dependabot/Renovate
"dependencies": { "jsonwebtoken": "^9.0.2" }
```

## A07: Identification and Authentication Failures

```typescript
// INSECURE — no rate limiting, session id in a non-HttpOnly cookie
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && user.password === req.body.password) {
    res.cookie('session', user.id);
    res.end();
  }
});

// SECURE — rate limiting + bcrypt verify + hardened cookie flags
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });

app.post('/login', loginLimiter, async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  const ok = user && (await bcrypt.compare(req.body.password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const sessionId = crypto.randomBytes(32).toString('base64url');
  await sessionStore.create(sessionId, user.id, { ttl: '15m' });

  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
  });
  res.end();
});
```

## A08: Software and Data Integrity Failures

```typescript
// INSECURE — trusts JWT without pinning algorithm/verifying signature
const payload = jwt.decode(token); // decode() does NOT verify signature!

// SECURE — verify signature and explicitly pin the algorithm
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

```typescript
// INSECURE — deserializing arbitrary untrusted data via eval/vm
const obj = eval('(' + req.body.data + ')');

// SECURE — JSON only, with schema validation
import { z } from 'zod';
const schema = z.object({ name: z.string(), age: z.number() });
const obj = schema.parse(JSON.parse(req.body.data));
```

## A09: Security Logging and Monitoring Failures

```typescript
// INSECURE — logs the password, no logging on auth failure
logger.info(`Login attempt: ${email} / ${password}`);
if (!authorized) return res.status(403).end();

// SECURE — structured logging without secrets; log security-relevant denials
logger.info('Login attempt', { email, outcome: authorized ? 'success' : 'failure', ip: req.ip });
if (!authorized) {
  logger.warn('Access denied', { userId: req.user?.id, path: req.path, ip: req.ip });
  return res.status(403).end();
}
```

## A10: Server-Side Request Forgery (SSRF)

```typescript
// INSECURE — fetches an attacker-controlled URL server-side
app.post('/link-preview', async (req, res) => {
  const response = await fetch(req.body.url); // could target http://169.254.169.254/...
  res.send(await response.text());
});

// SECURE — validate scheme/host, block private/link-local IPs, disable redirects
import { isIP } from 'net';
import dns from 'dns/promises';

const ALLOWLIST = new Set(['example.com', 'cdn.example.com']);

async function isPrivateOrLinkLocal(host: string): Promise<boolean> {
  const { address } = await dns.lookup(host);
  return (
    address.startsWith('127.') ||
    address.startsWith('10.') ||
    address.startsWith('192.168.') ||
    address.startsWith('169.254.') // covers cloud metadata endpoint
  );
}

app.post('/link-preview', async (req, res) => {
  const url = new URL(req.body.url);
  if (url.protocol !== 'https:' || !ALLOWLIST.has(url.hostname)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (!isIP(url.hostname) && (await isPrivateOrLinkLocal(url.hostname))) {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(3000) });
  res.send(await response.text());
});
```

## Quick Reference

| Category | Key library/pattern |
|----------|----------------------|
| A01 | Ownership checks in guards/middleware, never in the controller alone |
| A02 | `bcrypt`/`argon2`, `helmet` HSTS, secrets from env/secret manager |
| A03 | Parameterized queries (`pg`, `mysql2`), `execFile` over `exec`, React auto-escaping / DOMPurify |
| A04 | Server-side price/quantity recomputation, `express-rate-limit` on sensitive routes |
| A05 | `helmet`, environment-gated logging, strict CORS allowlist |
| A06 | `npm audit`, Dependabot/Renovate in CI |
| A07 | `express-rate-limit` on login, `bcrypt.compare`, `HttpOnly`/`Secure`/`SameSite` cookies |
| A08 | `jwt.verify` with pinned `algorithms`, `zod`/schema validation instead of `eval` |
| A09 | Structured logging (pino/winston) excluding secrets, alerting on repeated 401/403 |
| A10 | URL allowlisting, private-IP blocking, `redirect: 'manual'`, request timeouts |
