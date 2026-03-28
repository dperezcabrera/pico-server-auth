"""Example: wallet login flow (Ed25519).

Requires a running pico-server-auth instance.
Run the standalone example first, then:
    python examples/wallet_login.py
"""

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = "http://localhost:8100"


def main():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    address = "0x" + pk.public_bytes_raw().hex()[:40]

    with httpx.Client() as client:
        # 1. Request challenge
        r = client.post(f"{BASE}/auth/challenge", json={"address": address})
        r.raise_for_status()
        nonce = r.json()["challenge"]
        print(f"Challenge: {nonce[:16]}...")

        # 2. Sign the nonce
        signature = sk.sign(nonce.encode("utf-8"))

        # 3. Verify and get JWT
        r = client.post(
            f"{BASE}/auth/wallet",
            json={
                "address": address,
                "public_key": pk.public_bytes_raw().hex(),
                "signature": signature.hex(),
                "challenge": nonce,
                "algorithm": "Ed25519",
            },
        )
        r.raise_for_status()
        token = r.json()
        print(f"Address: {token['address']}")
        print(f"Token: {token['access_token'][:50]}...")

        # 4. Use the token
        r = client.get(
            f"{BASE}/auth/jwks",
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        print(f"JWKS: {r.status_code}")


if __name__ == "__main__":
    main()
