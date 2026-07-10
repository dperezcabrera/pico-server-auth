import pytest

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.wallet_verifier import WalletVerifier


@pytest.fixture
def verifier():
    settings = ServerAuthSettings(supported_wallet_algorithms=["ML-DSA-65", "Ed25519", "secp256k1"])
    return WalletVerifier(settings)


def test_unsupported_algorithm(verifier):
    with pytest.raises(ValueError, match="unsupported"):
        verifier.verify("RSA-2048", b"pk", b"msg", b"sig")


def test_ed25519_valid_signature(verifier):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    message = b"test challenge"
    signature = sk.sign(message)

    pk_bytes = pk.public_bytes_raw()
    assert verifier.verify("Ed25519", pk_bytes, message, signature) is True


def test_ed25519_invalid_signature(verifier):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes_raw()
    assert verifier.verify("Ed25519", pk_bytes, b"msg", b"bad" * 22) is False


def test_secp256k1_valid_signature(verifier):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    sk = ec.generate_private_key(ec.SECP256K1())
    pk = sk.public_key()
    message = b"test challenge"
    signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    r, s = decode_dss_signature(signature)
    if s > n // 2:
        signature = encode_dss_signature(r, n - s)

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert verifier.verify("secp256k1", pk_bytes, message, signature) is True


def test_secp256k1_high_s_signature_is_rejected(verifier):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    sk = ec.generate_private_key(ec.SECP256K1())
    pk = sk.public_key()
    message = b"test challenge"
    signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    r, s = decode_dss_signature(signature)
    high_s = encode_dss_signature(r, n - s if s <= n // 2 else s)

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert verifier.verify("secp256k1", pk_bytes, message, high_s) is False


def test_secp256k1_invalid_signature(verifier):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    sk = ec.generate_private_key(ec.SECP256K1())
    pk_bytes = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert verifier.verify("secp256k1", pk_bytes, b"msg", b"bad" * 20) is False


def test_supported_algorithm_without_verifier_raises():
    verifier = WalletVerifier(ServerAuthSettings(supported_wallet_algorithms=["RSA-2048"]))
    with pytest.raises(ValueError, match="no verifier"):
        verifier.verify("RSA-2048", b"pk", b"msg", b"sig")


def _mldsa_or_skip():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        pytest.skip("cryptography without ML-DSA support")
    return mldsa


def test_mldsa65_valid_signature(verifier):
    mldsa = _mldsa_or_skip()
    sk = mldsa.MLDSA65PrivateKey.generate()
    message = b"test challenge"
    signature = sk.sign(message)
    pk_bytes = sk.public_key().public_bytes_raw()
    assert verifier.verify("ML-DSA-65", pk_bytes, message, signature) is True


def test_mldsa65_invalid_signature(verifier):
    mldsa = _mldsa_or_skip()
    sk = mldsa.MLDSA65PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes_raw()
    assert verifier.verify("ML-DSA-65", pk_bytes, b"msg", b"garbage") is False


def _fake_dilithia(monkeypatch, adapter):
    import sys
    import types

    crypto = types.ModuleType("dilithia_sdk.crypto")
    crypto.load_native_crypto_adapter = lambda: adapter
    pkg = types.ModuleType("dilithia_sdk")
    pkg.crypto = crypto
    monkeypatch.setitem(sys.modules, "dilithia_sdk", pkg)
    monkeypatch.setitem(sys.modules, "dilithia_sdk.crypto", crypto)


def test_mldsa65_native_adapter_gets_exact_hex(verifier, monkeypatch):
    calls = {}

    class Adapter:
        def verify_message(self, pk_hex, msg_hex, sig_hex):
            calls["args"] = (pk_hex, msg_hex, sig_hex)
            return True

    _fake_dilithia(monkeypatch, Adapter())
    assert verifier.verify("ML-DSA-65", b"\x01", b"\x02", b"\x03") is True
    assert calls["args"] == ("01", "02", "03")


def test_mldsa65_null_native_adapter_falls_back(verifier, monkeypatch):
    _fake_dilithia(monkeypatch, None)
    mldsa = _mldsa_or_skip()
    sk = mldsa.MLDSA65PrivateKey.generate()
    message = b"test challenge"
    signature = sk.sign(message)
    assert verifier.verify("ML-DSA-65", sk.public_key().public_bytes_raw(), message, signature) is True


def test_mldsa65_no_backend_raises(verifier, monkeypatch):
    import sys

    from cryptography.hazmat.primitives import asymmetric

    monkeypatch.setitem(sys.modules, "dilithia_sdk", None)
    monkeypatch.setitem(sys.modules, "dilithia_sdk.crypto", None)
    monkeypatch.delattr(asymmetric, "mldsa", raising=False)
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.mldsa", None)
    with pytest.raises(RuntimeError, match="ML-DSA-65"):
        verifier.verify("ML-DSA-65", b"pk", b"msg", b"sig")
