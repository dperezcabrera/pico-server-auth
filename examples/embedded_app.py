"""Example: pico-server-auth embedded in an app alongside your own controllers.

Run:
    pip install pico-server-auth pico-client-auth uvicorn
    uvicorn examples.embedded_app:app --reload
"""

from fastapi import FastAPI
from pico_boot import init
from pico_client_auth import SecurityContext
from pico_fastapi import controller, get
from pico_ioc import DictSource, configuration


@controller(prefix="/api", tags=["App"])
class MyController:
    @get("/me")
    async def me(self):
        claims = SecurityContext.require()
        return {"sub": claims.sub, "role": getattr(claims, "role", None)}


config = configuration(
    DictSource({
        "fastapi": {"title": "My App", "version": "1.0.0"},
        "auth_client": {
            "enabled": True,
            "issuer": "http://localhost:8000",
            "audience": "my-app",
        },
        "server_auth": {
            "issuer": "http://localhost:8000",
            "audience": "my-app",
            "auto_create_admin": True,
            "admin_email": "admin@example.com",
            "admin_password": "admin",
        },
    })
)

container = init(modules=["pico_server_auth", "__main__"], config=config)
app: FastAPI = container.get(FastAPI)

# Now available:
#   POST /auth/challenge     — wallet login step 1
#   POST /auth/wallet        — wallet login step 2
#   POST /auth/login         — password login
#   GET  /auth/jwks          — JWKS for token validation
#   GET  /api/me             — your endpoint (requires valid JWT)
