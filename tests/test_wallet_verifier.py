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

    sk = ec.generate_private_key(ec.SECP256K1())
    pk = sk.public_key()
    message = b"test challenge"
    signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert verifier.verify("secp256k1", pk_bytes, message, signature) is True


def test_secp256k1_invalid_signature(verifier):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    sk = ec.generate_private_key(ec.SECP256K1())
    pk_bytes = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert verifier.verify("secp256k1", pk_bytes, b"msg", b"bad" * 20) is False
