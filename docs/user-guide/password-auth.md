# Password Authentication

Password authentication provides a simple email/password login for admin bootstrap scenarios. It is **disabled by default** and must be explicitly enabled.

!!! warning "Not for production user management"
    Password login uses static credentials from configuration. It is intended for initial admin access and development, not as a general-purpose user authentication system.

## Enabling Password Login

Set `auto_create_admin: true` in `ServerAuthSettings`:

```python
from pico_boot import Application

app = Application(
    module_names=["pico_server_auth"],
    config={
        "server_auth": {
            "auto_create_admin": True,
            "admin_email": "admin@example.com",
            "admin_password": "change-me-in-production",
            "issuer": "http://localhost:8100",
            "audience": "my-app",
        },
    },
)
```

## Login Request

```python
import httpx

async def admin_login(base_url: str, email: str, password: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        resp.raise_for_status()
        return resp.json()
        # {"access_token": "eyJ...", "refresh_token": "eyJ..."}
```

## Token Claims

Admin login tokens include:

| Claim | Value |
|---|---|
| `sub` | Admin email |
| `role` | `"admin"` |
| `iss` | Configured issuer |
| `aud` | Configured audience |
| `exp` | Expiry timestamp |

## Error Responses

| Status | Detail | Cause |
|---|---|---|
| `403` | `password login disabled` | `auto_create_admin` is `false` (default) |
| `401` | `invalid credentials` | Email or password does not match configuration |

## Configuration

| Setting | Type | Default | Description |
|---|---|---|---|
| `auto_create_admin` | `bool` | `False` | Enable password login endpoint |
| `admin_email` | `str` | `admin@pico.local` | Expected email for login |
| `admin_password` | `str` | `admin` | Expected password for login |
