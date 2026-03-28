"""Example: pico-server-auth as a standalone auth service.

Run:
    pip install pico-server-auth uvicorn
    uvicorn examples.standalone_auth:app --port 8100

Other services configure pico-client-auth to point here:
    auth_client:
      issuer: "http://localhost:8100"
      audience: "my-api"
"""

from fastapi import FastAPI
from pico_boot import init
from pico_ioc import DictSource, configuration

config = configuration(
    DictSource({
        "fastapi": {"title": "Auth Service", "version": "1.0.0"},
        "auth_client": {"enabled": False, "issuer": "", "audience": ""},
        "server_auth": {
            "issuer": "http://localhost:8100",
            "audience": "my-api",
            "auto_create_admin": True,
            "admin_email": "admin@example.com",
            "admin_password": "changeme",
            "supported_wallet_algorithms": ["ML-DSA-65", "Ed25519", "secp256k1"],
        },
    })
)

container = init(modules=["pico_server_auth"], config=config)
app: FastAPI = container.get(FastAPI)
