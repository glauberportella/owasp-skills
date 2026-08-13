# Node.js / TypeScript — OWASP API Security Patterns

Covers Express, Fastify, and NestJS. IDs reference `references/checklist.md` (API1-API10).

## BOLA — Object-Level Authorization (API1)

```typescript
// INSECURE — Express: fetches by ID with no ownership check
app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findByPk(req.params.id);
  res.json(invoice);
});

// SECURE — Express: scope the query to the authenticated user
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({
    where: { id: req.params.id, ownerId: req.user.id },
  });
  if (!invoice) return res.status(404).json({ error: 'Not found' });
  res.json(invoice);
});
```

```typescript
// SECURE — NestJS: authorization enforced via a guard + service-level scoping
@Get(':id')
@UseGuards(JwtAuthGuard)
async getInvoice(@Param('id') id: string, @CurrentUser() user: User) {
  const invoice = await this.invoicesService.findOwned(id, user.id);
  if (!invoice) throw new NotFoundException();
  return invoice;
}

// service
async findOwned(id: string, ownerId: string) {
  return this.repo.findOne({ where: { id, ownerId } }); // filter, not fetch-then-compare
}
```

## Broken Function-Level Authorization (API5)

```typescript
// INSECURE — NestJS: any authenticated user can hit this
@Delete(':id')
@UseGuards(JwtAuthGuard)
deleteUser(@Param('id') id: string) { ... }

// SECURE — NestJS: RolesGuard re-checks permission at the handler
@Delete(':id')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
deleteUser(@Param('id') id: string) { ... }
```

```typescript
// SECURE — Express: explicit middleware per route, not implicit from grouping
function requireRole(role: string) {
  return (req, res, next) =>
    req.user?.roles?.includes(role) ? next() : res.status(403).end();
}
app.delete('/api/users/:id', requireAuth, requireRole('admin'), deleteUserHandler);
```

## Mass Assignment / Property-Level Authorization (API3)

```typescript
// INSECURE — binds entire body to the entity
app.patch('/api/users/:id', async (req, res) => {
  await User.update(req.body, { where: { id: req.params.id } }); // role, balance writable
});

// SECURE — Zod schema as an explicit allow-list for input
import { z } from 'zod';

const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
}).strict(); // reject unknown keys, e.g. "role"

app.patch('/api/users/:id', requireAuth, async (req, res) => {
  const parsed = UpdateUserSchema.parse(req.body);
  if (req.user.id !== req.params.id) return res.status(403).end();
  await User.update(parsed, { where: { id: req.params.id } });
  res.json(toUserResponseDTO(await User.findByPk(req.params.id)));
});

// SECURE — explicit output DTO, never serialize the entity directly
function toUserResponseDTO(user: User) {
  return { id: user.id, name: user.name, email: user.email }; // no passwordHash, no role
}
```

```typescript
// SECURE — NestJS: class-validator DTO with whitelist enabled globally
// main.ts
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));

export class UpdateUserDto {
  @IsString() @MaxLength(100)
  name: string;

  @IsEmail()
  email: string;
  // role, balance intentionally absent — never bindable from the client
}
```

## Rate Limiting / Resource Consumption (API4, API6)

```typescript
// SECURE — Express: express-rate-limit per route
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,               // 10 attempts / 15 min / IP
  standardHeaders: true,
});
app.post('/api/login', authLimiter, loginHandler);

// SECURE — enforce server-side pagination ceiling
app.get('/api/search', async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 20, 100); // hard cap
  const results = await Item.findAll({ limit, offset: req.query.offset || 0 });
  res.json(results);
});
```

```typescript
// SECURE — Fastify: built-in @fastify/rate-limit plugin
import rateLimit from '@fastify/rate-limit';

await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (req) => req.headers['x-api-key'] ?? req.ip,
});
```

```typescript
// SECURE — sensitive business flow (API6): layered velocity check + CAPTCHA
app.post('/api/coupons/redeem', requireAuth, couponLimiter, async (req, res) => {
  const attempts = await redis.incr(`coupon:${req.user.id}`);
  if (attempts > 5) return res.status(429).json({ error: 'Too many attempts' });
  if (!(await verifyCaptcha(req.body.captchaToken))) return res.status(400).end();
  // ...redeem logic
});
```

## SSRF-Safe Outbound Calls (API7)

```typescript
// INSECURE — fetches whatever URL the client supplies
app.post('/api/import', async (req, res) => {
  const response = await fetch(req.body.url);
  res.send(await response.text());
});

// SECURE — validate scheme, resolve + check IP, allow-list host, no redirects
import { URL } from 'url';
import dns from 'dns/promises';
import ipaddr from 'ipaddr.js';

const ALLOWED_HOSTS = new Set(['partner-cdn.example.com']);

async function safeFetch(rawUrl: string) {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:') throw new Error('Invalid scheme');
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('Host not allowed');

  const { address } = await dns.lookup(url.hostname);
  const addr = ipaddr.process(address);
  if (addr.range() !== 'unicast') throw new Error('Blocked address range'); // blocks private/link-local/loopback

  return fetch(url.toString(), { redirect: 'error', signal: AbortSignal.timeout(3000) });
}
```

## Unsafe Consumption of Third-Party APIs (API10)

```typescript
// INSECURE — trusts and directly persists partner API response
const res = await fetch(partnerUrl);
const data = await res.json();
await User.create(data);

// SECURE — schema-validate, timeout, verify TLS, explicit mapping
import { z } from 'zod';

const PartnerUserSchema = z.object({
  externalId: z.string(),
  email: z.string().email(),
  name: z.string(),
});

const res = await fetch(partnerUrl, { signal: AbortSignal.timeout(5000) });
if (!res.ok) throw new Error(`Partner API error: ${res.status}`);
const parsed = PartnerUserSchema.parse(await res.json());
await User.create({ externalId: parsed.externalId, email: parsed.email, name: parsed.name });
```

## Security Misconfiguration Basics (API8)

```typescript
// SECURE — restrictive CORS, generic error handler, security headers
import helmet from 'helmet';
import cors from 'cors';

app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));

app.use((err, req, res, next) => {
  logger.error(err);                       // full detail server-side only
  res.status(500).json({ error: 'Internal server error' });
});
```
