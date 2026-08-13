# ASVS Secure Coding — Python

Concrete implementation guidance for Django, Flask, and FastAPI. ASVS chapter IDs are referenced so you can cross-check against `references/checklist.md`.

## Password Hashing (V2 Authentication)

Use `argon2-cffi` (Argon2id) directly, or Django's built-in hasher (already Argon2/PBKDF2-based when configured correctly).

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)

password_hash = ph.hash(plaintext_password)

try:
    ph.verify(password_hash, candidate_password)
    if ph.check_needs_rehash(password_hash):
        password_hash = ph.hash(candidate_password)  # upgrade on login
except VerifyMismatchError:
    raise AuthenticationError("Invalid credentials")
```

**Django**: set `Argon2PasswordHasher` first in `PASSWORD_HASHERS` so new hashes use it:

```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # fallback for existing hashes
]
```

Never use `hashlib.sha256(password.encode()).hexdigest()` for password storage — it is unsalted and fast.

## Sessions and JWT (V3 Session Management)

**Django** sessions are secure by default if configured:

```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 1800  # 30 min
CSRF_COOKIE_SECURE = True

# Rotate the session key on login (Django does this automatically via login()),
# but if managing sessions manually, always cycle the session key:
request.session.cycle_key()
```

**FastAPI/Flask JWT**, using `pyjwt`:

```python
import jwt
from datetime import datetime, timedelta, timezone

token = jwt.encode(
    {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
    private_key,
    algorithm="RS256",
)

# Verify: always pin algorithms explicitly
payload = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],   # never allow the token to dictate the algorithm
    audience="api",
    issuer="auth-service",
)
```

Pitfalls: `jwt.decode(token, options={"verify_signature": False})` disables verification entirely — never use it outside debugging. Keep access tokens short-lived and rotate refresh tokens stored in `HttpOnly` cookies.

## Access Control (V4)

**FastAPI** dependency-based enforcement, checked on every request:

```python
from fastapi import Depends, HTTPException

async def require_owner(document_id: str, current_user: User = Depends(get_current_user)) -> Document:
    doc = await get_document(document_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)  # avoid leaking existence via 403
    return doc

@app.get("/documents/{document_id}")
async def read_document(doc: Document = Depends(require_owner)):
    return doc
```

**Django**: use `permission_required`/DRF `permission_classes`, and object-level checks (e.g., `django-guardian`) rather than only view-level checks — a user having "view document" permission generally does not mean they own *this* document.

## Input Validation / Output Encoding (V5)

**FastAPI/Pydantic** validates at the boundary automatically — define strict models:

```python
from pydantic import BaseModel, Field, EmailStr

class CreateOrder(BaseModel):
    item_id: str = Field(..., pattern=r"^[0-9a-f-]{36}$")
    quantity: int = Field(..., gt=0, le=100)
```

**Django/Flask**: use Django Forms/DRF Serializers, or `marshmallow`/`pydantic` in Flask, rather than reading `request.POST`/`request.json` directly into queries.

SQL: use the ORM or parameterized cursor calls — never f-strings/`%`-formatting into SQL:

```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# GOOD
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
User.objects.filter(email=email)  # Django ORM parameterizes automatically
```

Django templates auto-escape HTML by default — avoid `{{ value|safe }}` and `mark_safe()` on user input. Jinja2 (Flask) also auto-escapes by default in `.html` templates; keep `autoescape` enabled.

Avoid `pickle.loads()` on any data that crosses a trust boundary (cache values from untrusted sources, uploaded files, request bodies) — use `json` instead.

## Secrets Management (V6, V14)

Use environment variables loaded via `os.environ`/`python-dotenv` locally, and a secret manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) in deployed environments. Validate at startup:

```python
import os

DB_PASSWORD = os.environ["DB_PASSWORD"]  # raises KeyError immediately if missing — fail fast
```

For Django, never leave `SECRET_KEY` as a hardcoded default in `settings.py` committed to source control; load it from the environment and set `DEBUG = False` in production.

Encryption at rest with the `cryptography` library (AES-GCM):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)  # from KMS in production, not generated ad hoc per record
nonce = os.urandom(12)  # unique per encryption call
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
```

## TLS / HTTPS Enforcement (V9)

```python
# Django
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SESSION_COOKIE_SECURE = True

# Outbound requests: never disable verification
import requests
requests.get(url)                  # verify=True is the default — keep it
requests.get(url, verify=False)    # NEVER do this in production code
```

## Secure File Upload (V12)

```python
import uuid
from pathlib import Path
import magic  # python-magic, reads actual file content

ALLOWED_MIME = {"image/png", "image/jpeg", "application/pdf"}
MAX_SIZE = 5 * 1024 * 1024
UPLOAD_DIR = Path("/var/app-data/uploads")  # outside webroot, not served directly

async def save_upload(file_bytes: bytes) -> str:
    if len(file_bytes) > MAX_SIZE:
        raise ValueError("File too large")
    detected_mime = magic.from_buffer(file_bytes, mime=True)
    if detected_mime not in ALLOWED_MIME:
        raise ValueError("Unsupported file type")
    stored_name = f"{uuid.uuid4()}"
    (UPLOAD_DIR / stored_name).write_bytes(file_bytes)
    return stored_name  # serve later through an authorized endpoint, not a static path
```

Never build the storage path from `file.filename` directly (path traversal via `../../etc/passwd`-style names) — always generate the filename server-side.
