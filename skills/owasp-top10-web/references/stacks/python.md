# OWASP Top 10 — Python Patterns

Idiomatic secure vs. insecure snippets for a typical Python stack
(Django, Flask, FastAPI, SQLAlchemy/psycopg2, passlib/argon2-cffi).

## A01: Broken Access Control

```python
# INSECURE — no ownership check, trusts the URL parameter
@app.route("/documents/<doc_id>")
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())

# SECURE — verify ownership server-side, default deny
@app.route("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first()
    if doc is None:
        abort(404)
    return jsonify(doc.to_dict())
```

```python
# SECURE — Django: use get_object_or_404 scoped to the requesting user
def document_detail(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    return JsonResponse(doc.to_dict())
```

## A02: Cryptographic Failures

```python
# INSECURE — MD5/SHA1 for passwords, hardcoded secret key
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
SECRET_KEY = "django-insecure-hardcoded-key"

# SECURE — argon2-cffi / passlib for password hashing, secret from env
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
ph.verify(password_hash, password)  # raises on mismatch

import os
SECRET_KEY = os.environ["SECRET_KEY"]
```

```python
# Django settings.py — SECURE production crypto/transport settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 63072000
```

## A03: Injection (SQL / Command / Template)

```python
# INSECURE — string-formatted SQL (psycopg2)
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")

# SECURE — parameterized query (psycopg2)
cur.execute("SELECT * FROM users WHERE email = %s", (email,))

# SECURE — SQLAlchemy ORM / Core with bound parameters
user = session.query(User).filter(User.email == email).first()
result = connection.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
```

```python
# INSECURE — shell injection via user input
import os
os.system(f"convert {filename} output.png")

# SECURE — no shell, argument list
import subprocess
subprocess.run(["convert", filename, "output.png"], check=True, shell=False)
```

```python
# INSECURE — Jinja2 autoescape disabled, or manual string building for HTML
template = Template("<div>{{ comment | safe }}</div>")  # 'safe' disables escaping

# SECURE — let autoescape do its job (default in Flask/Jinja2 for .html templates)
template = Template("<div>{{ comment }}</div>")  # auto-escaped
```

## A04: Insecure Design

```python
# INSECURE — trusts client-supplied total at checkout, no rate limiting
@app.route("/checkout", methods=["POST"])
def checkout():
    total = request.json["total"]  # attacker-controlled
    charge_card(current_user.id, total)

# SECURE — recompute price server-side, rate-limit the endpoint
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["5 per minute"])

@app.route("/checkout", methods=["POST"])
@limiter.limit("5 per minute")
@login_required
def checkout():
    cart_items = request.json["items"]
    total = compute_total_server_side(cart_items)  # server is source of truth
    if total <= 0:
        abort(400)
    charge_card(current_user.id, total)
```

## A05: Security Misconfiguration

```python
# INSECURE — Django debug mode and wildcard hosts in production
DEBUG = True
ALLOWED_HOSTS = ["*"]

# SECURE — hardened production settings
DEBUG = False
ALLOWED_HOSTS = ["example.com"]
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
```

```python
# INSECURE — leaks exception details to the client
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# SECURE — generic client-facing error, full detail only in logs
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Internal server error"}), 500
```

## A06: Vulnerable and Outdated Components

```bash
# Run in CI, fail on known vulnerabilities
pip-audit
safety check --full-report
```

```text
# INSECURE — requirements.txt with an old, vulnerable pin
Django==3.2.0

# SECURE — patched version, monitored via Dependabot/Renovate
Django==4.2.15
```

## A07: Identification and Authentication Failures

```python
# INSECURE — plaintext comparison, no rate limiting, weak session id
@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.json["email"]).first()
    if user and user.password == request.json["password"]:
        session["user_id"] = user.id  # fine, but nothing throttles brute force

# SECURE — hashed password verify + rate limiting + hardened session cookie
from argon2 import PasswordHasher
ph = PasswordHasher()

@app.route("/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login():
    user = User.query.filter_by(email=request.json["email"]).first()
    try:
        if user is None:
            raise Exception()
        ph.verify(user.password_hash, request.json["password"])
    except Exception:
        return jsonify({"error": "Invalid credentials"}), 401
    session["user_id"] = user.id

# app.config for Flask session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
)
```

## A08: Software and Data Integrity Failures

```python
# INSECURE — pickle on untrusted input allows arbitrary code execution
import pickle
data = pickle.loads(request.data)

# SECURE — JSON only, with schema validation
import json
from pydantic import BaseModel

class Payload(BaseModel):
    name: str
    age: int

data = Payload.model_validate(json.loads(request.data))
```

```python
# INSECURE — decodes JWT without verifying signature/algorithm
payload = jwt.decode(token, options={"verify_signature": False})

# SECURE — verify signature and pin expected algorithm
payload = jwt.decode(token, public_key, algorithms=["RS256"])
```

## A09: Security Logging and Monitoring Failures

```python
# INSECURE — logs the password, silent on authorization failure
logging.info(f"Login attempt: {email} / {password}")
if not authorized:
    return jsonify({"error": "forbidden"}), 403

# SECURE — structured logging without secrets, logs the denial
logging.info("Login attempt", extra={"email": email, "outcome": "success" if authorized else "failure", "ip": request.remote_addr})
if not authorized:
    logging.warning("Access denied", extra={"user_id": current_user.id, "path": request.path, "ip": request.remote_addr})
    return jsonify({"error": "forbidden"}), 403
```

## A10: Server-Side Request Forgery (SSRF)

```python
# INSECURE — fetches an attacker-controlled URL server-side
@app.route("/fetch-preview", methods=["POST"])
def fetch_preview():
    url = request.json["url"]
    resp = requests.get(url)  # could target http://169.254.169.254/latest/meta-data/
    return resp.text

# SECURE — allowlist host/scheme, block private/link-local IPs, disable redirects
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWLIST = {"example.com", "cdn.example.com"}

def is_private_or_link_local(host: str) -> bool:
    ip = socket.gethostbyname(host)
    return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_link_local

@app.route("/fetch-preview", methods=["POST"])
def fetch_preview():
    parsed = urlparse(request.json["url"])
    if parsed.scheme != "https" or parsed.hostname not in ALLOWLIST:
        abort(400)
    if is_private_or_link_local(parsed.hostname):
        abort(400)
    resp = requests.get(parsed.geturl(), allow_redirects=False, timeout=3)
    return resp.text
```

## Quick Reference

| Category | Key library/pattern |
|----------|----------------------|
| A01 | Query scoped by `owner`/`current_user`, `get_object_or_404` with ownership filter |
| A02 | `argon2-cffi`/`passlib`, Django `SECURE_*` settings, secrets via env/secret manager |
| A03 | psycopg2/SQLAlchemy bound parameters, `subprocess.run([...], shell=False)`, Jinja2 autoescape |
| A04 | Server-side recompute of price/quantity, `flask-limiter`/DRF throttling on sensitive flows |
| A05 | `DEBUG=False` in production, generic error handlers, Django security middleware |
| A06 | `pip-audit`/`safety`, Dependabot/Renovate on `requirements.txt`/`pyproject.toml` |
| A07 | Rate limiting on `/login`, Argon2 verify, `SESSION_COOKIE_HTTPONLY`/`SECURE`/`SAMESITE` |
| A08 | `pyjwt` with explicit `algorithms=[...]`, Pydantic schema validation instead of `pickle` |
| A09 | `logging` with structured `extra`, no secrets, alert on repeated 401/403 |
| A10 | URL allowlist, `ipaddress` private/link-local check, `allow_redirects=False`, `timeout` |
