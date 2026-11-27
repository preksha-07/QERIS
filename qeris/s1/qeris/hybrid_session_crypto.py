"""
QERIS in-process hybrid key exchange profile: X25519 + ML-KEM-768.

The profile uses the concatenated PQ/T hybrid key-agreement approach
described in RFC 9958 Section 13.1. Its fixed component-share and
shared-secret ordering matches the X25519MLKEM768 group defined for TLS 1.3
by RFC 10024:

  client share = ML-KEM-768 encapsulation key || X25519 public share
  server share = ML-KEM-768 ciphertext || X25519 public share
  combined IKM  = ML-KEM shared secret || X25519 shared secret

This module is an in-process QERIS simulator profile, NOT a TLS 1.3 or
DTLS 1.3 implementation. After the RFC-defined 64-byte concatenated IKM,
it applies QERIS's context-bound HKDF-SHA256 to derive the simulator's
AES-256-GCM key. Do not describe this module as RFC 10024 wire-protocol
interoperability.

No percentage weighting is used. Both components are executed, and both
shared secrets are included in the resulting key material.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import struct
from typing import Final

import oqs

from qeris_classical.session_crypto import (
    derive_shared_secret as x25519_derive_shared_secret,
    generate_keypair as x25519_generate_keypair,
)

HYBRID_GROUP: Final[str] = "X25519MLKEM768"
MLKEM_ALGORITHM: Final[str] = "ML-KEM-768"

MLKEM768_PUBLIC_KEY_LENGTH: Final[int] = 1184
MLKEM768_SECRET_KEY_LENGTH: Final[int] = 2400
MLKEM768_CIPHERTEXT_LENGTH: Final[int] = 1088
MLKEM768_SHARED_SECRET_LENGTH: Final[int] = 32

X25519_PUBLIC_KEY_LENGTH: Final[int] = 32
X25519_PRIVATE_KEY_LENGTH: Final[int] = 32
X25519_SHARED_SECRET_LENGTH: Final[int] = 32

CLIENT_KEY_SHARE_LENGTH: Final[int] = (
    MLKEM768_PUBLIC_KEY_LENGTH + X25519_PUBLIC_KEY_LENGTH
)  # 1216
SERVER_KEY_SHARE_LENGTH: Final[int] = (
    MLKEM768_CIPHERTEXT_LENGTH + X25519_PUBLIC_KEY_LENGTH
)  # 1120
COMBINED_SHARED_SECRET_LENGTH: Final[int] = (
    MLKEM768_SHARED_SECRET_LENGTH + X25519_SHARED_SECRET_LENGTH
)  # 64

HASH_LENGTH: Final[int] = 32
SESSION_KEY_LENGTH: Final[int] = 32
HYBRID_HKDF_SALT: Final[bytes] = b"QERIS-HYBRID-HKDF-SHA256-SALT-v1"
HYBRID_HKDF_LABEL: Final[bytes] = b"QERIS-HYBRID-SESSION-KEY-v1"
HYBRID_TRANSCRIPT_LABEL: Final[bytes] = b"QERIS-X25519MLKEM768-TRANSCRIPT-v1\x00"


class HybridCryptoInputError(ValueError):
    """Raised when a hybrid key share, key or context is malformed."""


@dataclass(frozen=True)
class HybridKeyPair:
    """Client-side ephemeral keypair; secret fields are excluded from repr."""

    mlkem_public_key: bytes
    mlkem_secret_key: bytes = field(repr=False)
    x25519_public_key: bytes
    x25519_private_key: bytes = field(repr=False)

    @property
    def client_key_share(self) -> bytes:
        """RFC 10024 X25519MLKEM768 client-share ordering."""
        return self.mlkem_public_key + self.x25519_public_key


@dataclass(frozen=True)
class HybridEncapsulation:
    """Server-side response share and combined shared secret."""

    server_key_share: bytes
    combined_shared_secret: bytes = field(repr=False)


def _require_bytes(name: str, value: bytes, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    result = bytes(value)
    if len(result) != length:
        raise HybridCryptoInputError(
            f"{name} must be exactly {length} bytes; got {len(result)}"
        )
    return result


def _require_context_string(name: str, value: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise HybridCryptoInputError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise HybridCryptoInputError(f"{name} must be valid UTF-8") from exc
    if len(encoded) > 65535:
        raise HybridCryptoInputError(f"{name} exceeds 65535 UTF-8 bytes")
    return encoded


def _context_info(
    *,
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> bytes:
    fields = (
        _require_context_string("device_id", device_id),
        _require_context_string("flow_id", flow_id),
        _require_context_string("sensitivity_tier", sensitivity_tier),
    )
    if type(policy_version) is not int or policy_version < 1:
        raise HybridCryptoInputError("policy_version must be an integer >= 1")
    info = bytearray(HYBRID_HKDF_LABEL)
    for item in fields:
        info.extend(struct.pack(">I", len(item)))
        info.extend(item)
    info.extend(struct.pack(">Q", policy_version))
    return bytes(info)


def _require_mlkem_enabled() -> None:
    if MLKEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError(
            f"{MLKEM_ALGORITHM} is not enabled in this liboqs build. "
            "Hybrid X25519MLKEM768 requires liboqs with ML-KEM-768 support."
        )


def generate_hybrid_keypair() -> HybridKeyPair:
    """Generate fresh ML-KEM-768 and X25519 client ephemeral keypairs."""
    _require_mlkem_enabled()
    kem = None
    try:
        kem = oqs.KeyEncapsulation(MLKEM_ALGORITHM)
        mlkem_pk = bytes(kem.generate_keypair())
        mlkem_sk = bytes(kem.export_secret_key())
    finally:
        if kem is not None:
            kem.free()

    x25519_pk, x25519_sk = x25519_generate_keypair()
    return HybridKeyPair(
        mlkem_public_key=_require_bytes(
            "ML-KEM-768 public key", mlkem_pk, MLKEM768_PUBLIC_KEY_LENGTH
        ),
        mlkem_secret_key=_require_bytes(
            "ML-KEM-768 secret key", mlkem_sk, MLKEM768_SECRET_KEY_LENGTH
        ),
        x25519_public_key=_require_bytes(
            "X25519 public key", x25519_pk, X25519_PUBLIC_KEY_LENGTH
        ),
        x25519_private_key=_require_bytes(
            "X25519 private key", x25519_sk, X25519_PRIVATE_KEY_LENGTH
        ),
    )


def encapsulate_hybrid(client_key_share: bytes) -> HybridEncapsulation:
    """Server encapsulation over an RFC 10024-shaped X25519MLKEM768 client share."""
    share = _require_bytes(
        "client_key_share", client_key_share, CLIENT_KEY_SHARE_LENGTH
    )
    mlkem_pk = share[:MLKEM768_PUBLIC_KEY_LENGTH]
    client_x25519_pk = share[MLKEM768_PUBLIC_KEY_LENGTH:]

    _require_mlkem_enabled()
    kem = None
    try:
        kem = oqs.KeyEncapsulation(MLKEM_ALGORITHM)
        ciphertext, mlkem_ss = kem.encap_secret(mlkem_pk)
    finally:
        if kem is not None:
            kem.free()

    ciphertext = _require_bytes(
        "ML-KEM-768 ciphertext", ciphertext, MLKEM768_CIPHERTEXT_LENGTH
    )
    mlkem_ss = _require_bytes(
        "ML-KEM-768 shared secret", mlkem_ss, MLKEM768_SHARED_SECRET_LENGTH
    )

    server_x25519_pk, server_x25519_sk = x25519_generate_keypair()
    x25519_ss = x25519_derive_shared_secret(server_x25519_sk, client_x25519_pk)
    x25519_ss = _require_bytes(
        "X25519 shared secret", x25519_ss, X25519_SHARED_SECRET_LENGTH
    )

    # RFC 10024 Section 4.3 order for X25519MLKEM768 is ML-KEM first, X25519 second.
    combined = mlkem_ss + x25519_ss
    return HybridEncapsulation(
        server_key_share=ciphertext + _require_bytes(
            "server X25519 public key", server_x25519_pk, X25519_PUBLIC_KEY_LENGTH
        ),
        combined_shared_secret=_require_bytes(
            "combined hybrid shared secret", combined, COMBINED_SHARED_SECRET_LENGTH
        ),
    )


def decapsulate_hybrid(
    server_key_share: bytes,
    client_keypair: HybridKeyPair,
) -> bytes:
    """Client decapsulation/ECDH over the server's RFC 10024-shaped share."""
    share = _require_bytes(
        "server_key_share", server_key_share, SERVER_KEY_SHARE_LENGTH
    )
    if not isinstance(client_keypair, HybridKeyPair):
        raise TypeError("client_keypair must be a HybridKeyPair")

    mlkem_ciphertext = share[:MLKEM768_CIPHERTEXT_LENGTH]
    server_x25519_pk = share[MLKEM768_CIPHERTEXT_LENGTH:]

    _require_mlkem_enabled()
    kem = None
    try:
        kem = oqs.KeyEncapsulation(
            MLKEM_ALGORITHM, secret_key=client_keypair.mlkem_secret_key
        )
        mlkem_ss = kem.decap_secret(mlkem_ciphertext)
    finally:
        if kem is not None:
            kem.free()

    mlkem_ss = _require_bytes(
        "ML-KEM-768 shared secret", mlkem_ss, MLKEM768_SHARED_SECRET_LENGTH
    )
    x25519_ss = x25519_derive_shared_secret(
        client_keypair.x25519_private_key, server_x25519_pk
    )
    x25519_ss = _require_bytes(
        "X25519 shared secret", x25519_ss, X25519_SHARED_SECRET_LENGTH
    )

    # Preserve the standardized component order; no percentage weighting.
    combined = mlkem_ss + x25519_ss
    return _require_bytes(
        "combined hybrid shared secret", combined, COMBINED_SHARED_SECRET_LENGTH
    )


def derive_hybrid_session_key(
    combined_shared_secret: bytes,
    *,
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
    handshake_id: str,
) -> bytes:
    """Derive an AES-256 key bound to the hybrid transcript and flow context.

    The HKDF info includes the SHA-256 transcript hash over both complete key
    shares, device/flow/sensitivity context and policy version. This is QERIS's
    application-specific RFC 5869 HKDF-SHA256 derivation, not the TLS 1.3
    key schedule.
    """
    ikm = _require_bytes(
        "combined_shared_secret",
        combined_shared_secret,
        COMBINED_SHARED_SECRET_LENGTH,
    )
    if (
        not isinstance(handshake_id, str)
        or len(handshake_id) != 64
        or any(ch not in "0123456789abcdef" for ch in handshake_id)
    ):
        raise HybridCryptoInputError(
            "handshake_id must be a 64-character lowercase SHA-256 hex digest"
        )
    transcript_digest = bytes.fromhex(handshake_id)
    info = _context_info(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=sensitivity_tier,
        policy_version=policy_version,
    )
    info += struct.pack(">I", len(transcript_digest)) + transcript_digest
    prk = hmac.new(HYBRID_HKDF_SALT, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < SESSION_KEY_LENGTH:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:SESSION_KEY_LENGTH])


def hybrid_shared_secret_fingerprint(combined_shared_secret: bytes) -> str:
    """Return a SHA-256 diagnostic fingerprint; never expose component secrets."""
    secret = _require_bytes(
        "combined_shared_secret",
        combined_shared_secret,
        COMBINED_SHARED_SECRET_LENGTH,
    )
    return hashlib.sha256(secret).hexdigest()


def compute_hybrid_handshake_id(
    client_key_share: bytes,
    server_key_share: bytes,
    *,
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> str:
    """Hash both component shares and policy context for simulator correlation.

    This identifier is not a TLS Finished value and does not authenticate the
    transcript by itself. Device authentication remains a separate operation.
    """
    client_share = _require_bytes(
        "client_key_share", client_key_share, CLIENT_KEY_SHARE_LENGTH
    )
    server_share = _require_bytes(
        "server_key_share", server_key_share, SERVER_KEY_SHARE_LENGTH
    )
    context = _context_info(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=sensitivity_tier,
        policy_version=policy_version,
    )
    transcript = bytearray(HYBRID_TRANSCRIPT_LABEL)
    for item in (client_share, server_share, context):
        transcript.extend(struct.pack(">I", len(item)))
        transcript.extend(item)
    return hashlib.sha256(transcript).hexdigest()
