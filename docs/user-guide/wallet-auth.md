# Wallet Authentication

Wallet authentication uses a challenge/verify flow: the client requests a nonce, signs it with their private key, and submits the signature. The server verifies the signature against the provided public key and issues a JWT.

## Flow Overview

1. **Request challenge** — `POST /auth/challenge` with the wallet address.
2. **Sign challenge** — The client signs the nonce with their private key.
3. **Verify and login** — `POST /auth/wallet` with address, public key, signature, challenge, and algorithm.
4. **Receive JWT** — The server returns access and refresh tokens.

## Step 1: Request a Challenge

```python
import httpx

async def request_challenge(base_url: str, address: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/auth/challenge",
            json={"address": address},
        )
        resp.raise_for_status()
        return resp.json()
        # {"challenge": "<64-char hex nonce>", "ttl": 60}
```

The returned `challenge` is a hex-encoded random nonce (32 bytes / 64 hex chars). It expires after `ttl` seconds (default: 60).

## Step 2: Sign the Challenge

The client signs the challenge nonce bytes with their private key. The exact method depends on the algorithm.

=== "ML-DSA-65"

    ```python
    from cryptography.hazmat.primitives.asymmetric import mldsa

    # Generate keypair (or load existing)
    private_key = mldsa.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()

    # Sign the challenge nonce
    message = challenge_nonce.encode("utf-8")
    signature = private_key.sign(message)

    # Hex-encode for the API
    public_key_hex = public_key.public_bytes_raw().hex()
    signature_hex = signature.hex()
    algorithm = "ML-DSA-65"
    ```

=== "Ed25519"

    ```python
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # Generate keypair (or load existing)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Sign the challenge nonce
    message = challenge_nonce.encode("utf-8")
    signature = private_key.sign(message)

    # Hex-encode for the API
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    public_key_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    signature_hex = signature.hex()
    algorithm = "Ed25519"
    ```

=== "secp256k1"

    ```python
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Generate keypair (or load existing)
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    # Sign the challenge nonce
    message = challenge_nonce.encode("utf-8")
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    # Hex-encode for the API (uncompressed point encoding)
    public_key_hex = public_key.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ).hex()
    signature_hex = signature.hex()
    algorithm = "secp256k1"
    ```

## Step 3: Verify and Login

```python
async def wallet_login(base_url: str, address: str, public_key_hex: str,
                       signature_hex: str, challenge: str, algorithm: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/auth/wallet",
            json={
                "address": address,
                "public_key": public_key_hex,
                "signature": signature_hex,
                "challenge": challenge,
                "algorithm": algorithm,
            },
        )
        resp.raise_for_status()
        return resp.json()
        # {
        #   "access_token": "eyJ...",
        #   "refresh_token": "eyJ...",
        #   "address": "0x...",
        #   "algorithm": "ML-DSA-65"
        # }
```

## Step 4: Use the JWT

The returned `access_token` is a standard RS256 JWT. Include it in subsequent requests:

```python
headers = {"Authorization": f"Bearer {tokens['access_token']}"}
```

pico-client-auth validates the token automatically via middleware.

## Full Example — ML-DSA-65

```python
import httpx
from cryptography.hazmat.primitives.asymmetric import mldsa

BASE_URL = "http://localhost:8100"
ADDRESS = "0xPostQuantumWallet001"

# 1. Generate keys
private_key = mldsa.MLDSA65PrivateKey.generate()
public_key = private_key.public_key()

async def authenticate():
    async with httpx.AsyncClient() as client:
        # 2. Request challenge
        resp = await client.post(
            f"{BASE_URL}/auth/challenge",
            json={"address": ADDRESS},
        )
        challenge = resp.json()["challenge"]

        # 3. Sign challenge
        message = challenge.encode("utf-8")
        signature = private_key.sign(message)

        # 4. Submit for verification
        resp = await client.post(
            f"{BASE_URL}/auth/wallet",
            json={
                "address": ADDRESS,
                "public_key": public_key.public_bytes_raw().hex(),
                "signature": signature.hex(),
                "challenge": challenge,
                "algorithm": "ML-DSA-65",
            },
        )
        tokens = resp.json()
        print(f"Access token: {tokens['access_token'][:50]}...")
        return tokens
```

## Token Claims

Wallet login tokens include these claims:

| Claim | Value |
|---|---|
| `sub` | Wallet address |
| `role` | `"wallet"` |
| `algorithm` | Signing algorithm used (e.g., `"ML-DSA-65"`) |
| `wallet_address` | Wallet address (same as `sub`) |
| `iss` | Configured issuer |
| `aud` | Configured audience |
| `exp` | Expiry timestamp |

## Security Notes

!!! warning "Challenge nonces are single-use"
    Each challenge nonce is consumed on verification. A nonce cannot be reused even if verification fails due to an invalid signature.

!!! info "Public keys are not stored"
    pico-server-auth verifies signatures but does not store public keys or maintain a user registry. The `address` field is an opaque identifier chosen by the client.
