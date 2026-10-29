"""
QERIS Step 2: ML-KEM-512 and context-bound session-key derivation.

This module is isolated from policy verification and gateway integration.
It uses real liboqs-python ML-KEM-512 operations and the Python standard
library for HKDF-SHA256. It never logs or prints secret material.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Final

import oqs

KEM_ALGORITHM: Final[str] = "ML-KEM-512"
HASH_LENGTH: Final[int] = 32
HKDF_SALT: Final[bytes] = b"QERIS-HKDF-SHA256-SALT-v1"
HKDF_LABEL: Final[bytes] = b"QERIS-SESSION-KEY-v1"
SESSION_KEY_LENGTH: Final[int] = 32

# FIPS 203 ML-KEM-512 encoded lengths, in bytes.
PUBLIC_KEY_LENGTH: Final[int] = 800
SECRET_KEY_LENGTH: Final[int] = 1632
CIPHERTEXT_LENGTH: Final[int] = 768
SHARED_SECRET_LENGTH: Final[int] = 32


class CryptoInputError(ValueError):
    """Raised when cryptographic input is malformed or out of bounds."""


def _require_bytes(name: str, value: bytes, expected_length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    result = bytes(value)
    if len(result) != expected_length:
        raise CryptoInputError(
            f"{name} must be exactly {expected_length} bytes; got {len(result)}"
        )
    return result


def _require_context_string(name: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value or not value.strip():
        raise CryptoInputError(f"{name} must not be empty or whitespace-only")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CryptoInputError(f"{name} must be valid UTF-8 text") from exc
    if len(encoded) > 65535:
        raise CryptoInputError(f"{name} is too long (maximum 65535 UTF-8 bytes)")
    return encoded


def _context_info(
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> bytes:
    """Encode context unambiguously using length-prefixed UTF-8 fields."""
    fields = (
        _require_context_string("device_id", device_id),
        _require_context_string("flow_id", flow_id),
        _require_context_string("sensitivity_tier", sensitivity_tier),
    )
    if type(policy_version) is not int or policy_version < 1:
        raise CryptoInputError("policy_version must be an integer >= 1 (not bool)")
    encoded = bytearray(HKDF_LABEL)
    for field in fields:
        encoded.extend(struct.pack(">I", len(field)))
        encoded.extend(field)
    encoded.extend(struct.pack(">Q", policy_version))
    return bytes(encoded)


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh ML-KEM-512 keypair.

    Returns (public_key, secret_key). The caller must protect the secret key
    and must never log it. For production use, store it only in an approved
    protected key store; this prototype does not provide persistent storage.
    """
    if KEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError(f"{KEM_ALGORITHM} is not enabled in this liboqs build")
    kem = None
    try:
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        public_key = bytes(kem.generate_keypair())
        secret_key = bytes(kem.export_secret_key())
        return (
            _require_bytes("generated public key", public_key, PUBLIC_KEY_LENGTH),
            _require_bytes("generated secret key", secret_key, SECRET_KEY_LENGTH),
        )
    finally:
        if kem is not None:
            kem.free()


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared_secret) for an ML-KEM-512 recipient."""
    public_key = _require_bytes("public_key", public_key, PUBLIC_KEY_LENGTH)
    if KEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError(f"{KEM_ALGORITHM} is not enabled in this liboqs build")
    kem = None
    try:
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return (
            _require_bytes("ciphertext", ciphertext, CIPHERTEXT_LENGTH),
            _require_bytes("shared_secret", shared_secret, SHARED_SECRET_LENGTH),
        )
    finally:
        if kem is not None:
            kem.free()


def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate a correctly sized ciphertext using an ML-KEM-512 secret key."""
    ciphertext = _require_bytes("ciphertext", ciphertext, CIPHERTEXT_LENGTH)
    secret_key = _require_bytes("secret_key", secret_key, SECRET_KEY_LENGTH)
    if KEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise RuntimeError(f"{KEM_ALGORITHM} is not enabled in this liboqs build")
    kem = None
    try:
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return _require_bytes("decapsulated shared_secret", shared_secret, SHARED_SECRET_LENGTH)
    finally:
        if kem is not None:
            kem.free()


def _hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = HKDF_SALT) -> bytes:
    """RFC 5869 HKDF using HMAC-SHA256; internal helper."""
    if not ikm:
        raise CryptoInputError("ikm must not be empty")
    if length < 1 or length > 255 * HASH_LENGTH:
        raise CryptoInputError("HKDF output length is out of range")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
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
    """
    Derive a 256-bit session key with HKDF-SHA256.

    The shared secret is input key material only; it is never used directly
    as an AEAD key. Context fields are bound into HKDF's info value.
    """
    shared_secret = _require_bytes(
        "shared_secret", shared_secret, SHARED_SECRET_LENGTH
    )
    info = _context_info(device_id, flow_id, sensitivity_tier, policy_version)
    return _hkdf_sha256(shared_secret, info, SESSION_KEY_LENGTH)


def shared_secret_fingerprint(shared_secret: bytes) -> str:
    """Return a non-secret SHA-256 fingerprint for diagnostics/tests only."""
    shared_secret = _require_bytes(
        "shared_secret", shared_secret, SHARED_SECRET_LENGTH
    )
    return hashlib.sha256(shared_secret).hexdigest()
