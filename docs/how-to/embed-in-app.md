# Embed in App

Run pico-server-auth inside your pico-boot application so auth endpoints and your business logic share the same process.

## Setup

Include both `pico_server_auth` and `pico_client_auth` in your module list. Match the `issuer` and `audience` settings between them.

```python
from pico_boot import Application

app = Application(
    module_names=[
        "pico_server_auth",   # /auth/* endpoints (issue tokens)
        "pico_client_auth",   # JWT validation middleware (validate tokens)
        "my_app",             # Your controllers
    ],
    config={
        "server_auth": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "access_token_expire_minutes": 30,
            "refresh_token_expire_days": 7,
            "challenge_ttl_seconds": 120,
            "supported_wallet_algorithms": ["ML-DSA-65", "Ed25519", "secp256k1"],
        },
        "auth_client": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "jwks_url": "http://localhost:8100/api/v1/auth/jwks",
        },
    },
)

app.run()
```

## Your Controllers

Your controllers use pico-client-auth decorators as usual. Tokens issued by pico-server-auth are validated transparently.

```python
from pico_fastapi import controller, get
from pico_client_auth import requires_role, SecurityContext

@controller(prefix="/api", tags=["API"])
class MyController:

    @requires_role("admin")
    @get("/admin/dashboard")
    async def admin_dashboard(self):
        ctx = SecurityContext.current()
        return {"message": f"Welcome, {ctx.claims.sub}"}

    @get("/profile")
    async def profile(self):
        ctx = SecurityContext.current()
        return {
            "subject": ctx.claims.sub,
            "role": ctx.claims.role,
        }
```

## Enabling Admin Bootstrap

To allow initial admin access via password login, enable `auto_create_admin`:

```python
config = {
    "server_auth": {
        "auto_create_admin": True,
        "admin_email": "admin@example.com",
        "admin_password": "secure-password-here",
        # ... other settings
    },
}
```

## What You Get

| Endpoint | Source | Auth Required |
|---|---|---|
| `GET /api/v1/auth/jwks` | pico-server-auth | No |
| `POST /api/v1/auth/challenge` | pico-server-auth | No |
| `POST /api/v1/auth/sign-in` | pico-server-auth | No |
| `POST /api/v1/auth/login` | pico-server-auth | No |
| `GET /api/admin/dashboard` | Your app | Yes (admin role) |
| `GET /api/profile` | Your app | Yes (any authenticated) |

All auth endpoints are marked with `@allow_anonymous` so they bypass pico-client-auth's JWT validation middleware.
