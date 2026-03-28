"""pico-server-auth: embeddable auth server module.

Auto-discovered by pico-boot via the ``pico_boot.modules`` entry point.
Provides JWT issuance, wallet challenge/verify login, password login,
and JWKS endpoint as FastAPI controllers.

Compatible with pico-client-auth — tokens issued here are validated
by pico-client-auth in the same process or across services.
"""

from .challenge_store import ChallengeStore as ChallengeStore
from .challenge_store import InMemoryChallengeStore as InMemoryChallengeStore
from .config import ServerAuthSettings as ServerAuthSettings
from .token_issuer import TokenIssuer as TokenIssuer
from .wallet_verifier import WalletVerifier as WalletVerifier
