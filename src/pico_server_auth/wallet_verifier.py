from pico_ioc import component

from pico_server_auth.config import ServerAuthSettings


@component
class WalletVerifier:
    """Verifies wallet signatures for challenge-response auth.

    Supports ML-DSA-65, Ed25519, and secp256k1. Each algorithm
    is loaded on first use to avoid hard dependencies.
    """

    def __init__(self, settings: ServerAuthSettings):
        self._supported = set(settings.supported_wallet_algorithms)

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if algorithm not in self._supported:
            raise ValueError(f"unsupported wallet algorithm: {algorithm}")

        if algorithm == "ML-DSA-65":
            return self._verify_mldsa65(public_key, message, signature)
        elif algorithm == "Ed25519":
            return self._verify_ed25519(public_key, message, signature)
        elif algorithm == "secp256k1":
            return self._verify_secp256k1(public_key, message, signature)
        else:
            raise ValueError(f"no verifier for algorithm: {algorithm}")

    @staticmethod
    def _verify_mldsa65(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa

            pk = mldsa.MLDSA65PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def _verify_secp256k1(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes

            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
