# Java — Dependency & Secrets Hygiene

## Dependency Auditing

**OWASP Dependency-Check** is the standard SCA tool for the JVM ecosystem,
matching resolved dependencies against the NVD.

```bash
# Maven plugin
mvn org.owasp:dependency-check-maven:check

# Gradle plugin (build.gradle)
plugins {
    id "org.owasp.dependencycheck" version "9.2.0"
}
# then:
./gradlew dependencyCheckAnalyze
```

```xml
<!-- pom.xml -->
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.2.0</version>
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
  </configuration>
  <executions>
    <execution>
      <goals><goal>check</goal></goals>
    </execution>
  </executions>
</plugin>
```

Requires a free NVD API key set as `NVD_API_KEY` (or via plugin config) so
the local vulnerability data feed updates in a reasonable time; without one
the first sync can take a very long time.

**Alternative/complementary:** Snyk (`snyk test` against `pom.xml`/
`build.gradle`) and Trivy (`trivy fs .`) both understand Maven/Gradle
lockfiles and are faster to bootstrap in CI than Dependency-Check.

## Pinning & Lockfiles

**Maven** resolves the same versions given the same `pom.xml` inputs, but
transitive versions can still shift as upstream POMs change. Lock them
explicitly:

```bash
# Maven dependency plugin — snapshot the fully resolved tree
mvn dependency:tree -Dverbose > dependency-tree.txt

# Or use the Maven "Dependency Lock" style: pin exact versions in
# <dependencyManagement>, and avoid version ranges like [1.0,2.0) entirely.
```

Prefer pinning every direct dependency to an exact version in
`<dependencyManagement>` and avoiding version ranges — Maven has no
first-class lockfile equivalent to `package-lock.json`, so explicit exact
pins are your lockfile.

**Gradle** has native dependency locking:

```groovy
// build.gradle
dependencyLocking {
    lockAllConfigurations()
}
```

```bash
./gradlew dependencies --write-locks   # generates gradle.lockfile
./gradlew build                        # fails if resolution drifts from the lock
```

Commit the generated `gradle.lockfile` (or per-configuration lock files).
Re-run `--write-locks` deliberately when you intend to change versions —
never hand-edit the lock file.

## Loading Secrets Safely

```java
// Read from environment — never hardcode
String apiKey = System.getenv("STRIPE_SECRET_KEY");
if (apiKey == null || apiKey.isEmpty()) {
    throw new IllegalStateException("STRIPE_SECRET_KEY is not set");
}
```

```java
// Spring Boot: externalize via application.yml + env var placeholders
// application.yml
// stripe:
//   secret-key: ${STRIPE_SECRET_KEY}

@Value("${stripe.secret-key}")
private String stripeSecretKey;
```

- Never commit `application.yml`/`application.properties` with real
  credentials — use `${ENV_VAR}` placeholders and inject the real value at
  deploy time via the platform, or use Spring Cloud Config / Vault
  integration for centralized secret management.
- `application-local.yml` or any profile file containing real local
  secrets belongs in `.gitignore`, mirroring `.env` in other stacks.
- For Vault-backed apps, use `spring-cloud-vault-config` rather than
  fetching and caching secrets by hand — it handles renewal/rotation.
- Never log full JDBC connection strings, `Authorization` headers, or
  request bodies containing credentials — mask them in logging filters
  (e.g., Logback pattern filters or a custom `MDC` scrubber).

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

      - uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '21'

      - name: OWASP Dependency-Check (Maven)
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7

      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
