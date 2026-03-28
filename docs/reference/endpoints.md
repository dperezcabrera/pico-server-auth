# Endpoints Reference

All endpoints are served by `AuthController` under the `/auth` prefix with tag `"Auth"`. All endpoints are public (`@allow_anonymous`).

---

## GET /api/v1/auth/jwks

Returns the JWKS (JSON Web Key Set) containing the public key used to sign JWTs.

**Authentication:** None required.

**Response:** `200 OK`

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "pico-server-auth-1",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded RSA modulus>",
      "e": "AQAB"
    }
  ]
}
```

---

## POST /api/v1/auth/challenge

Request a challenge nonce for wallet authentication.

**Authentication:** None required.

**Request body:**

```json
{
  "address": "0xYourWalletAddress"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | `string` | Yes | Wallet address (opaque identifier) |

**Response:** `200 OK`

```json
{
  "challenge": "a1b2c3d4e5f6...64-char-hex-nonce",
  "ttl": 60
}
```

| Field | Type | Description |
|---|---|---|
| `challenge` | `string` | 64-character hex-encoded random nonce |
| `ttl` | `integer` | Nonce validity in seconds |

**Errors:**

| Status | Detail | Cause |
|---|---|---|
| `400` | `address required` | Missing or empty `address` field |

---

## POST /api/v1/auth/sign-in

Verify a wallet signature and issue JWT tokens.

**Authentication:** None required.

**Request body:**

```json
{
  "address": "0xYourWalletAddress",
  "public_key": "hex-encoded-public-key",
  "signature": "hex-encoded-signature",
  "challenge": "the-challenge-nonce",
  "algorithm": "ML-DSA-65"
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `address` | `string` | Yes | — | Wallet address |
| `public_key` | `string` | Yes | — | Hex-encoded public key |
| `signature` | `string` | Yes | — | Hex-encoded signature of the challenge nonce |
| `challenge` | `string` | Yes | — | The nonce from `/api/v1/auth/challenge` |
| `algorithm` | `string` | No | `"ML-DSA-65"` | Signature algorithm: `"ML-DSA-65"`, `"Ed25519"`, or `"secp256k1"` |

**Response:** `200 OK`

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "address": "0xYourWalletAddress",
  "algorithm": "ML-DSA-65"
}
```

| Field | Type | Description |
|---|---|---|
| `access_token` | `string` | RS256 JWT access token |
| `refresh_token` | `string` | RS256 JWT refresh token |
| `address` | `string` | Wallet address (echo) |
| `algorithm` | `string` | Algorithm used (echo) |

**Access token claims:**

```json
{
  "sub": "0xYourWalletAddress",
  "iss": "http://localhost:8100",
  "aud": "pico",
  "iat": 1711612800,
  "exp": 1711613700,
  "role": "wallet",
  "algorithm": "ML-DSA-65",
  "wallet_address": "0xYourWalletAddress"
}
```

**Errors:**

| Status | Detail | Cause |
|---|---|---|
| `400` | `address, public_key, signature, and challenge required` | Missing required fields |
| `400` | `invalid hex encoding` | `public_key` or `signature` is not valid hex |
| `401` | `invalid or expired challenge` | Nonce not found, already used, or expired |
| `401` | `signature verification failed` | Signature does not match public key |

---

## POST /api/v1/auth/login

Password-based login for admin bootstrap.

**Authentication:** None required.

**Prerequisite:** `auto_create_admin` must be `true` in `ServerAuthSettings`.

**Request body:**

```json
{
  "email": "admin@pico.local",
  "password": "admin"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | `string` | Yes | Admin email |
| `password` | `string` | Yes | Admin password |

**Response:** `200 OK`

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Access token claims:**

```json
{
  "sub": "admin@pico.local",
  "iss": "http://localhost:8100",
  "aud": "pico",
  "iat": 1711612800,
  "exp": 1711613700,
  "role": "admin"
}
```

**Errors:**

| Status | Detail | Cause |
|---|---|---|
| `403` | `password login disabled` | `auto_create_admin` is `false` |
| `401` | `invalid credentials` | Email or password does not match |
