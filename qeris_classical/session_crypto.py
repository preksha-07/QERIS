"""Classical QERIS session cryptography: X25519 + HKDF-SHA256.

This module is intentionally independent of liboqs and does not modify the
existing QERIS PQC modules. It implements a local two-endpoint handshake for
demonstration/testing; it is not a network transport protocol.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

KEY_EXCHANGE_ALGORITHM: Final[str] = "X25519"
HASH_LENGTH: Final[int] = 32
SHARED_SECRET_LENGTH: Final[int] = 32
SESSION_KEY_LENGTH: Final[int] = 32
PUBLIC_KEY_LENGTH: Final[int] = 32
PRIVATE_KEY_LENGTH: Final[int] = 32
HKDF_SALT: Final[bytes] = b"QERIS-HKDF-SHA256-SALT-v1"
HKDF_LABEL: Final[bytes] = b"QERIS-SESSION-KEY-v1"


class ClassicalCryptoInputError(ValueError):
    """Raised when a classical cryptographic input is malformed."""


def _require_bytes(name: str, value: bytes, expected_length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    result = bytes(value)
    if len(result) != expected_length:
        raise ClassicalCryptoInputError(
            f"{name} must be exactly {expected_length} bytes; got {len(result)}"
        )
    return result


def _require_context_string(name: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value or not value.strip():
        raise ClassicalCryptoInputError(f"{name} must not be empty or whitespace-only")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ClassicalCryptoInputError(f"{name} must be valid UTF-8 text") from exc
    if len(encoded) > 65535:
        raise ClassicalCryptoInputError(f"{name} is too long (maximum 65535 UTF-8 bytes)")
    return encoded


def _context_info(
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> bytes:
    """Match S1's unambiguous, length-prefixed HKDF context encoding."""
    fields = (
        _require_context_string("device_id", device_id),
        _require_context_string("flow_id", flow_id),
        _require_context_string("sensitivity_tier", sensitivity_tier),
    )
    if type(policy_version) is not int or policy_version < 1:
        raise ClassicalCryptoInputError("policy_version must be an integer >= 1 (not bool)")
    encoded = bytearray(HKDF_LABEL)
    for field in fields:
        encoded.extend(struct.pack(">I", len(field)))
        encoded.extend(field)
    encoded.extend(struct.pack(">Q", policy_version))
    return bytes(encoded)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair; return (raw_public_key, raw_private_key).

    The private key is raw key material. Protect it and never log or transmit it.
    This helper is for ephemeral/demo key exchange, not persistent identity keys.
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return (
        _require_bytes("generated public key", public_bytes, PUBLIC_KEY_LENGTH),
        _require_bytes("generated private key", private_bytes, PRIVATE_KEY_LENGTH),
    )


def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Perform X25519 ECDH and return the 32-byte shared secret."""
    private_bytes = _require_bytes("private_key", private_key, PRIVATE_KEY_LENGTH)
    public_bytes = _require_bytes("peer_public_key", peer_public_key, PUBLIC_KEY_LENGTH)
    try:
        local_private = X25519PrivateKey.from_private_bytes(private_bytes)
        peer_public = X25519PublicKey.from_public_bytes(public_bytes)
        shared_secret = local_private.exchange(peer_public)
    except (ValueError, TypeError) as exc:
        raise ClassicalCryptoInputError("X25519 key agreement failed") from exc
    # X25519's exchange operation rejects an all-zero shared secret in
    # cryptography; retain an explicit check as defense in depth.
    if hmac.compare_digest(shared_secret, b"\x00" * SHARED_SECRET_LENGTH):
        raise ClassicalCryptoInputError("X25519 produced an invalid all-zero shared secret")
    return _require_bytes("shared_secret", shared_secret, SHARED_SECRET_LENGTH)


def _hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = HKDF_SALT) -> bytes:
    """RFC 5869 HKDF-SHA256, matching the S1 implementation."""
    if not ikm:
        raise ClassicalCryptoInputError("ikm must not be empty")
    if length < 1 or length > 255 * HASH_LENGTH:
        raise ClassicalCryptoInputError("HKDF output length is out of range")
    pseudorandom_key = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_session_key(
    shared_secret: bytes,
    *,
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> bytes:
    """Derive a context-bound 256-bit AES key from the X25519 shared secret."""
    secret = _require_bytes("shared_secret", shared_secret, SHARED_SECRET_LENGTH)
    info = _context_info(device_id, flow_id, sensitivity_tier, policy_version)
    return _hkdf_sha256(secret, info, SESSION_KEY_LENGTH)


def shared_secret_fingerprint(shared_secret: bytes) -> str:
    """Return a non-secret SHA-256 fingerprint suitable for tests/diagnostics."""
    secret = _require_bytes("shared_secret", shared_secret, SHARED_SECRET_LENGTH)
    return hashlib.sha256(secret).hexdigest()
