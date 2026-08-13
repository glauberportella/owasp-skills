# Node.js / TypeScript — Dependency & Secrets Hygiene

## Dependency Auditing

```bash
# npm
npm audit
npm audit --audit-level=high
npm audit fix                    # apply safe/non-breaking fixes automatically
npm audit fix --force            # may include breaking major upgrades — review before running

# yarn (classic v1)
yarn audit
yarn audit --level high

# pnpm
pnpm audit
pnpm audit --prod                # exclude devDependencies
```

For a transitive vulnerability with no upstream fix yet, pin the patched
version directly:

```jsonc
// package.json (npm >= 8.3 / pnpm)
"overrides": {
  "vulnerable-package": "^2.1.4"
}
```

```jsonc
// package.json (yarn classic)
"resolutions": {
  "vulnerable-package": "^2.1.4"
}
```

## Pinning & Lockfiles

- Always commit **one** lockfile per project — `package-lock.json`,
  `yarn.lock`, or `pnpm-lock.yaml` — matching whichever package manager the
  team standardized on. Mixing lockfiles across contributors causes drift
  and defeats the point of locking.
- Use `npm ci` (not `npm install`) in CI and Docker builds — it installs
  exactly what's in the lockfile and fails if `package.json` and the
  lockfile disagree, instead of silently re-resolving versions.
- Avoid unpinned ranges like `"lodash": "*"`; prefer caret ranges
  (`^4.17.21`) with a committed lockfile so the *resolved* version is
  reproducible even though the declared range allows updates.
- Run `npm outdated` / `pnpm outdated` periodically to see what's drifting
  from latest, separate from the security-specific audit.

## Loading Secrets Safely

```ts
// Load once at startup — dotenv only for local dev, never in production images
import 'dotenv/config';

const apiKey = process.env.STRIPE_SECRET_KEY;
if (!apiKey) {
  throw new Error('STRIPE_SECRET_KEY is not set');
}
```

- `dotenv` (and `.env` files) are a **local development convenience only**.
  In staging/production, inject env vars via the platform (container
  orchestrator secrets, cloud provider secret manager, CI/CD secret store)
  — do not ship a `.env` file inside a deployed container image.
- Never `import` or bundle `.env` values into client-side code — anything
  processed by a frontend bundler (Vite, webpack, Next.js `NEXT_PUBLIC_*`,
  CRA `REACT_APP_*`) ends up in the shipped JS and is publicly readable.
  Only prefix a variable that way if it is genuinely safe to expose (e.g.,
  a public analytics ID), never an API secret.
- Validate required env vars at startup (fail fast) rather than discovering
  a missing secret deep in a request handler.
- `.gitignore` must include `.env`, `.env.local`, `.env.*.local` before the
  first commit; commit a `.env.example` with placeholder keys only.

## CI Snippet (GitHub Actions)

```yaml
name: dependency-and-secrets-check

on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so gitleaks can scan past commits

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies (respects lockfile exactly)
        run: npm ci

      - name: npm audit (fail on high/critical)
        run: npm audit --audit-level=high

      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
