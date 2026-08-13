# ASVS Secure Coding — Node.js / TypeScript

Concrete implementation guidance for Express, Fastify, NestJS, and Next.js API routes. ASVS chapter IDs are referenced so you can cross-check against `references/checklist.md`.

## Password Hashing (V2 Authentication)

Use `argon2` (Argon2id) or `bcrypt`. Avoid `crypto.createHash('sha256')` for passwords — it is fast by design, which is the opposite of what you want.

```typescript
import argon2 from 'argon2';

// Hashing
const hash = await argon2.hash(plaintextPassword, {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MB
  timeCost: 2,
  parallelism: 1,
});

// Verifying
const valid = await argon2.verify(hash, candidatePassword);
```

If `argon2` native bindings are unavailable in your deployment target, `bcrypt`/`bcryptjs` with cost factor 12+ is an acceptable fallback.

```typescript
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const valid = await bcrypt.compare(password, hash);
```

Never compare hashes with `===`; always use the library's constant-time `verify`/`compare`.

## Sessions and JWT (V3 Session Management)

**Cookie-based sessions** (preferred for browser apps — tokens never touch JS-accessible storage):

```typescript
app.use(session({
  secret: process.env.SESSION_SECRET!,
  cookie: {
    secure: true,      // HTTPS only
    httpOnly: true,     // not readable via JS -> mitigates XSS token theft
    sameSite: 'lax',    // or 'strict' for high-sensitivity apps
    maxAge: 30 * 60 * 1000, // 30 min idle timeout
  },
  resave: false,
  saveUninitialized: false,
}));

// Regenerate session ID on login to prevent fixation
app.post('/login', async (req, res) => {
  // ...verify credentials...
  req.session.regenerate((err) => {
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});
```

**JWT** (for APIs / stateless auth), using `jsonwebtoken`:

```typescript
import jwt from 'jsonwebtoken';

// Sign with an explicit algorithm and short expiry
const token = jwt.sign({ sub: user.id }, privateKey, {
  algorithm: 'RS256',
  expiresIn: '15m',
  issuer: 'auth-service',
  audience: 'api',
});

// Verify: pin algorithms explicitly to avoid algorithm-confusion attacks
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'], // never omit — prevents 'none'/HS256-vs-RS256 confusion
  issuer: 'auth-service',
  audience: 'api',
});
```

Pitfalls specific to `jsonwebtoken`:
- Never call `jwt.decode()` for authorization decisions — it does not verify the signature.
- Store the refresh token in an `HttpOnly` cookie, not `localStorage`; rotate it on each use and revoke the old one (maintain a server-side refresh-token allow/deny list or use short-lived rotation).
- Keep access-token lifetime short (5–15 min) since JWTs cannot be revoked without extra infrastructure.

## Access Control (V4)

Centralize checks as middleware/guards; never rely on hiding a route.

```typescript
function requireOwnership(resourceLoader: (id: string) => Promise<{ ownerId: string } | null>) {
  return async (req, res, next) => {
    const resource = await resourceLoader(req.params.id);
    if (!resource || resource.ownerId !== req.user.id) {
      return res.status(404).end(); // don't leak existence via 403 vs 404
    }
    req.resource = resource;
    next();
  };
}

router.get('/documents/:id', requireAuth, requireOwnership(loadDocument), handler);
```

In NestJS, implement this as a `Guard` combined with `@UseGuards()`; do not scatter `if (req.user.role !== 'admin')` checks across controllers.

## Input Validation / Output Encoding (V5)

Use `zod` (or `class-validator` in NestJS) for schema validation at the boundary — validate before any business logic runs.

```typescript
import { z } from 'zod';

const CreateOrderSchema = z.object({
  itemId: z.string().uuid(),
  quantity: z.number().int().positive().max(100),
});

app.post('/orders', (req, res) => {
  const parsed = CreateOrderSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });
  // parsed.data is now safe to use
});
```

SQL: always parameterize (works the same with `pg`, `mysql2`, Prisma, TypeORM's query builder):

```typescript
await pool.query('SELECT * FROM users WHERE email = $1', [email]); // safe
// Prisma / TypeORM equivalents already parameterize when using their query APIs
```

React/JSX auto-escapes interpolated values — avoid `dangerouslySetInnerHTML`. If raw HTML is unavoidable, sanitize first:

```typescript
import DOMPurify from 'isomorphic-dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userHtml) }} />
```

## Secrets Management (V6, V14)

- Load via `process.env`, populated from a secret manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Doppler) in CI/CD — never commit `.env` files with real values.
- Validate required env vars at startup (fail fast) using a schema, e.g. `envsafe`/`zod`.

```typescript
const EnvSchema = z.object({
  DB_PASSWORD: z.string().min(1),
  JWT_PRIVATE_KEY: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
});
const env = EnvSchema.parse(process.env); // throws at boot if misconfigured
```

- For encryption at rest, use Node's `crypto` module with AES-256-GCM and a fresh IV per call:

```typescript
import crypto from 'crypto';
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

## TLS / HTTPS Enforcement (V9)

```typescript
// Redirect HTTP to HTTPS and set HSTS (e.g., via helmet)
import helmet from 'helmet';
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
}));

// Outbound calls: never disable certificate verification
axios.get(url); // default TLS verification stays on — don't set `rejectUnauthorized: false`
```

## Secure File Upload (V12)

Use `multer` with in-memory storage, validate content, then persist to object storage outside the webroot.

```typescript
import multer from 'multer';
import { fileTypeFromBuffer } from 'file-type';
import crypto from 'crypto';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB cap
});

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  const detected = await fileTypeFromBuffer(req.file.buffer);
  const allowed = ['image/png', 'image/jpeg', 'application/pdf'];
  if (!detected || !allowed.includes(detected.mime)) {
    return res.status(400).json({ error: 'Unsupported file type' });
  }
  const storedName = `${crypto.randomUUID()}.${detected.ext}`;
  await s3.putObject({ Bucket: UPLOAD_BUCKET, Key: storedName, Body: req.file.buffer });
  // Bucket is not web-servable directly; serve via a signed URL or authorized controller
  res.json({ id: storedName });
});
```

Never write uploads into `./public` or any directory served statically by Express/Nginx.
