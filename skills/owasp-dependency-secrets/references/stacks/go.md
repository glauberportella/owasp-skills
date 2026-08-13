# Go — Dependency & Secrets Hygiene

## Dependency Auditing

**govulncheck** (official Go team tool) checks your code and its module
dependencies against the Go vulnerability database, and — unlike a naive
version-only scan — reports only vulnerabilities in code paths your program
actually calls, which cuts noise significantly.

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest

govulncheck ./...
govulncheck -json ./... > govulncheck-report.json
```

**Trivy** also understands `go.sum` for a quick version-based scan and adds
container/IaC/secret coverage in the same run:

```bash
trivy fs --scanners vuln .
```

**Snyk** is a further option (`snyk test`) if you want a hosted dashboard
and auto-fix PRs across a polyglot org.

## Pinning & Lockfiles

Go modules are pinned by default via `go.mod` (direct/indirect version
constraints) and `go.sum` (cryptographic checksums of every module version
in the build), so lockfile discipline is largely built in — the main risks
are drift and unverified sums.

```bash
go mod tidy              # sync go.mod/go.sum with actual imports
go mod verify             # verify downloaded modules match go.sum checksums
go mod download           # populate module cache from go.sum

# Upgrade a specific dependency deliberately (not go get -u ./... blindly)
go get example.com/some/module@v1.4.2
go mod tidy
```

- **Commit `go.sum`** — it is the checksum lockfile; without it, builds
  aren't reproducible and can silently pull a tampered module version.
  `go.mod` alone is not enough.
  Never delete `go.sum` to "fix" a resolution conflict — fix the actual
  version constraint instead.
- Avoid `go get -u ./...` (upgrade everything) as a routine habit; upgrade
  one module at a time so you can attribute a break or a new advisory to
  the right change.
- Set `GOFLAGS=-mod=readonly` (or rely on the Go 1.16+ default) in CI so a
  build fails loudly instead of silently rewriting `go.mod`/`go.sum`.
- Enable `GOSUMDB` (on by default) so module downloads are checked against
  the public checksum database, guarding against a compromised or
  malicious module proxy serving tampered code.

## Loading Secrets Safely

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	apiKey := os.Getenv("STRIPE_SECRET_KEY")
	if apiKey == "" {
		panic("STRIPE_SECRET_KEY is not set")
	}
	fmt.Println("loaded key, length:", len(apiKey))
}
```

```go
// github.com/joho/godotenv — local development convenience only
import "github.com/joho/godotenv"

func init() {
	// Safe to ignore the error in dev if .env is optional; don't do this in prod images
	_ = godotenv.Load()
}
```

- `godotenv` (or similar `.env` loaders) should only run in local
  development. Production binaries typically run in containers or on hosts
  where real env vars are injected by the orchestrator/secret manager —
  don't bundle a `.env` file into a deployed container image.
- For anything beyond a single local dev loop, prefer a secret manager SDK
  (AWS Secrets Manager, GCP Secret Manager, Vault) over a flat env var,
  especially for values that need rotation.
- Never `fmt.Println`/`log.Printf` a full secret value, even during
  debugging — log its presence/length or a redacted prefix instead, and
  remove debug logging before merging.
- `.gitignore` must include `.env` and any `*.local.env` before the first
  commit; commit only a `.env.example` with placeholder values.

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
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Verify module checksums
        run: go mod verify

      - name: govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...

      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
