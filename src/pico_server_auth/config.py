from dataclasses import dataclass, field

from pico_ioc import configured


@configured(target="self", prefix="server_auth", mapping="tree")
@dataclass
class ServerAuthSettings:
    """Configuration for pico-server-auth.

    When embedded alongside pico-client-auth, set ``issuer`` and ``audience``
    to the same values so tokens issued here are accepted by the client middleware.
    """

    issuer: str = "http://localhost:8100"
    audience: str = "pico"
    algorithm: str = "RS256"
    # Access token: a working day by default. Pair with the
    # refresh-token flow if you want shorter blast radius.
    access_token_expire_minutes: int = 480
    refresh_token_expire_days: int = 7
    challenge_ttl_seconds: int = 60
    auto_create_admin: bool = False
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
    # Role stamped on tokens minted by the password-login flow.
    # Defaults to "operator" — what fleet-* services expect for
    # the human-operator surface. Deployments that want a stricter
    # split (admin vs operator) can override.
    admin_role: str = "operator"
    supported_wallet_algorithms: list[str] = field(default_factory=lambda: ["ML-DSA-65", "Ed25519", "secp256k1"])

    # ── fleet session-token mint endpoint ────────────────────────
    # When set, ``POST /api/v1/auth/fleet/sessions`` is enabled and
    # callers must present this value in the ``X-Fleet-Secret``
    # header. fleet-runtime is the only intended caller. Empty
    # disables the endpoint entirely (fail-closed).
    fleet_mint_secret: str = ""
    # Default TTL when callers don't specify one. Long enough that
    # routine workloads never re-mint, short enough to bound damage
    # if the operator forgets to revoke. Override per-deployment.
    fleet_session_ttl_seconds: int = 86400   # 24 h default
    # Hard ceiling — caller-supplied TTLs above this are clamped.
    # Memory: feedback_no_time_expiry.md — fleet policy is "tokens
    # invalidated only by revocation, not time". We default to
    # 100 years here so the existing clamp is effectively a no-op,
    # while keeping the knob for deployments that prefer a stricter
    # ceiling (set via env / configurer).
    fleet_max_ttl_seconds: int = 100 * 365 * 86400

    # ── Revocation persistence ───────────────────────────────────
    # Path to a JSON-Lines file the revocation store appends to.
    # Empty = use the in-memory store (revocations lost on restart).
    # When set, every revoke is durably persisted; existing entries
    # are loaded on startup. Operators in production should set
    # this to a path on a persistent volume.
    revocation_store_path: str = ""

    # ── Mint audit log ───────────────────────────────────────────
    # Path to a JSON-Lines file the issuer appends to on every
    # token mint. Powers the operator's "live tokens" view (and,
    # by subtraction with the revocation log, "what's still
    # valid"). Empty = in-memory mirror, reset on restart.
    mint_audit_path: str = ""
    # Don't audit ephemeral mints below this TTL — pre-filter
    # the high-volume per-dispatch agent_tokens (60s TTL) so the
    # log doesn't drown the long-lived tokens the operator
    # actually wants to manage. Override with 0 to audit
    # everything.
    mint_audit_min_ttl_seconds: int = 60 * 5
    # In-memory cap for the audit deque. The persistent file
    # grows monotonically (use logrotate for disk compaction);
    # this knob bounds RAM usage + the working set the SPA reads.
    # Newest N kept; older entries stay on disk for forensic
    # grep / external tooling. Operators with millions of mints
    # / year should pair this with a logrotate config.
    mint_audit_max_in_memory: int = 5000
