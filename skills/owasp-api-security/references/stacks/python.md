# Python — OWASP API Security Patterns

Covers FastAPI (Pydantic, slowapi) and Django REST Framework (permission classes, django-ratelimit). IDs reference `references/checklist.md` (API1-API10).

## BOLA — Object-Level Authorization (API1)

```python
# INSECURE — FastAPI: fetches by ID with no ownership check
@router.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int, db: Session = Depends(get_db)):
    return db.query(Invoice).filter(Invoice.id == invoice_id).first()

# SECURE — FastAPI: scope the query to the current user
@router.get("/invoices/{invoice_id}")
async def get_invoice(
    invoice_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    invoice = (
        db.query(Invoice)
        .filter(Invoice.id == invoice_id, Invoice.owner_id == current_user.id)
        .first()
    )
    if invoice is None:
        raise HTTPException(status_code=404, detail="Not found")
    return invoice
```

```python
# INSECURE — DRF: generic view with no object-level permission
class InvoiceDetail(RetrieveAPIView):
    queryset = Invoice.objects.all()
    permission_classes = [IsAuthenticated]  # authenticated, but not scoped

# SECURE — DRF: custom permission class enforces ownership per object
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id

class InvoiceDetail(RetrieveAPIView):
    queryset = Invoice.objects.all()
    permission_classes = [IsAuthenticated, IsOwner]
    # DRF calls has_object_permission automatically via get_object()
```

## Broken Function-Level Authorization (API5)

```python
# INSECURE — FastAPI: only checks authentication, not role
@router.delete("/users/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    db.delete(user_id)

# SECURE — FastAPI: dependency enforces role at the handler
def require_role(role: str):
    def checker(current_user: User = Depends(get_current_user)):
        if role not in current_user.roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return current_user
    return checker

@router.delete("/users/{user_id}")
async def delete_user(user_id: int, admin: User = Depends(require_role("admin"))):
    db.delete(user_id)
```

```python
# SECURE — DRF: permission class checks role, not just IsAuthenticated
class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"

class UserDetail(DestroyAPIView):
    permission_classes = [IsAdmin]
```

## Mass Assignment / Property-Level Authorization (API3)

```python
# INSECURE — binds entire request body onto the ORM model
@router.patch("/users/{user_id}")
async def update_user(user_id: int, payload: dict, db: Session = Depends(get_db)):
    user = db.query(User).get(user_id)
    for key, value in payload.items():
        setattr(user, key, value)   # attacker sends {"role": "admin"}
    db.commit()

# SECURE — Pydantic schema as an explicit input allow-list
from pydantic import BaseModel, EmailStr

class UpdateUserRequest(BaseModel):
    name: str
    email: EmailStr
    # role, balance intentionally absent — never bindable from client input
    model_config = {"extra": "forbid"}  # reject unknown fields

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    # explicit output allow-list — no password_hash, no role

@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id != user_id:
        raise HTTPException(status_code=403)
    user = db.query(User).get(user_id)
    user.name = payload.name
    user.email = payload.email
    db.commit()
    return user
```

```python
# SECURE — DRF: serializer explicitly lists writable fields
class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["name", "email"]  # role/balance excluded -> not mass-assignable

class UserResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "name", "email"]  # explicit output allow-list
```

## Rate Limiting / Resource Consumption (API4, API6)

```python
# SECURE — FastAPI: slowapi rate limiter per route
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@router.post("/login")
@limiter.limit("10/15minutes")
async def login(request: Request, credentials: LoginRequest):
    ...

# SECURE — server-enforced pagination ceiling
@router.get("/search")
async def search(limit: int = 20, offset: int = 0):
    limit = min(limit, 100)  # hard cap regardless of client input
    return db.query(Item).offset(offset).limit(limit).all()
```

```python
# SECURE — Django: django-ratelimit decorator on a sensitive view
from django_ratelimit.decorators import ratelimit

@ratelimit(key="user_or_ip", rate="5/h", block=True)
def redeem_coupon(request):
    ...
```

```python
# SECURE — business flow abuse (API6): velocity check + CAPTCHA before redeeming
@router.post("/coupons/redeem")
@limiter.limit("5/hour")
async def redeem_coupon(payload: RedeemRequest, current_user: User = Depends(get_current_user)):
    if not verify_captcha(payload.captcha_token):
        raise HTTPException(status_code=400, detail="CAPTCHA failed")
    ...
```

## SSRF-Safe Outbound Calls (API7)

```python
# INSECURE — fetches whatever URL the client supplies
@router.post("/import")
async def import_from_url(payload: ImportRequest):
    response = requests.get(payload.url)
    return response.text

# SECURE — validate scheme, resolve + check IP range, allow-list host, no redirects
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"partner-cdn.example.com"}

def safe_fetch(raw_url: str) -> requests.Response:
    parsed = urlparse(raw_url)
    if parsed.scheme != "https":
        raise ValueError("Invalid scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

    resolved_ip = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("Blocked address range")

    return requests.get(raw_url, timeout=3, allow_redirects=False)
```

## Unsafe Consumption of Third-Party APIs (API10)

```python
# INSECURE — trusts and directly persists partner API response
response = requests.get(partner_url, timeout=None, verify=False)
User.objects.create(**response.json())

# SECURE — schema-validate, timeout, keep TLS verification on, explicit mapping
from pydantic import BaseModel, EmailStr

class PartnerUserSchema(BaseModel):
    external_id: str
    email: EmailStr
    name: str

response = requests.get(partner_url, timeout=5, verify=True)
response.raise_for_status()
parsed = PartnerUserSchema.model_validate(response.json())
User.objects.create(external_id=parsed.external_id, email=parsed.email, name=parsed.name)
```

## Security Misconfiguration Basics (API8)

```python
# SECURE — FastAPI: disable docs/debug in production, generic error handler
app = FastAPI(
    docs_url=None if settings.ENV == "production" else "/docs",
    debug=(settings.ENV != "production"),
)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(exc)  # full detail server-side only
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

```python
# SECURE — Django settings.py: production hardening
DEBUG = False
ALLOWED_HOSTS = ["api.example.com"]
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS_ALLOW_CREDENTIALS = True
SECURE_HSTS_SECONDS = 31536000
```
