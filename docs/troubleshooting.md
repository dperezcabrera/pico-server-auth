# Troubleshooting

## Challenge expired

```
401 — invalid or expired challenge
```

The challenge nonce has a TTL (default 60s). Request a new one and sign it immediately.

Configure TTL via `server_auth.challenge_ttl_seconds`.

## Algorithm not supported

```
400 — unsupported wallet algorithm: X
```

Only algorithms listed in `server_auth.supported_wallet_algorithms` are accepted. Default: ML-DSA-65, Ed25519, secp256k1.

## ML-DSA-65 verification fails

```
RuntimeError: ML-DSA-65 verification requires dilithia-sdk[native] or cryptography>=44.0
```

Install one of:
- `pip install dilithia-sdk[native]` — exact Dilithia blockchain compatibility
- `pip install cryptography>=44.0` — when FIPS 204 support is available

## JWKS fetch failed (pico-client-auth)

If pico-client-auth can't validate tokens:

**Same process**: ensure both `pico_server_auth` and `pico_client_auth` are in the modules list, and `auth_client.issuer` matches `server_auth.issuer`.

**Separate processes**: ensure `auth_client.jwks_endpoint` or `auth_client.issuer` points to the service running pico-server-auth.

## Password login disabled

```
403 — password login disabled
```

Set `server_auth.auto_create_admin: true` to enable the admin password login endpoint.

## Signature verification failed

```
401 — signature verification failed
```

Check that:
1. The challenge nonce was signed as UTF-8 bytes
2. The public key matches the address that requested the challenge
3. The algorithm field matches how the signature was created
4. Keys are hex-encoded (not base64)
