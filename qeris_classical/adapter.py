"""Standalone classical-mode session adapter for later QERIS integration.

API shape is intentionally close to qeris.s2.crypto_adapter.establish_session.
This file is not wired into the gateway; the integrator must add mode dispatch
behind the existing policy and S3 security-floor checks.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac

from .secure_message import MessageContext, MessageDecryptor, MessageEncryptor
from .session_crypto import derive_session_key, derive_shared_secret, generate_keypair


class UnsupportedCryptoModeError(NotImplementedError):
    """Raised for modes other than CLASSICAL in this add-on."""


class CryptoPreconditionError(RuntimeError):
    """Raised when the handshake or QERIS context preconditions are violated."""


@dataclass
class ClassicalCryptoSession:
    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    mode: str
    key_exchange: str
    device_public_key: bytes
    gateway_public_key: bytes
    _encryptor: MessageEncryptor
    _decryptor: MessageDecryptor

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError(f"Plaintext must be bytes-like, got {type(plaintext).__name__}")
        return self._encryptor.encrypt(bytes(plaintext))

    def decrypt(self, envelope: bytes) -> bytes:
        if not isinstance(envelope, (bytes, bytearray, memoryview)):
            raise TypeError(f"Envelope must be bytes-like, got {type(envelope).__name__}")
        return self._decryptor.decrypt(bytes(envelope))


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    mode: str = "CLASSICAL",
) -> ClassicalCryptoSession:
    """Simulate a two-endpoint X25519 handshake and establish one-way AES-GCM.

    The function locally generates both endpoint keypairs to support the same
    loopback demonstration pattern used by the current QERIS PQC adapter. A
    real transport integration must exchange public keys between endpoints,
    authenticate/bind those keys to the peer identity, and derive each side's
    session key independently; this function itself does not authenticate the
    X25519 public keys against a remote identity.
    """
    if not isinstance(mode, str):
        raise CryptoPreconditionError("mode must be a string")
    normalized_mode = mode.strip().upper()
    if normalized_mode != "CLASSICAL":
        raise UnsupportedCryptoModeError(
            f"This add-on implements only CLASSICAL (X25519 + HKDF-SHA256 + AES-256-GCM); got {mode!r}"
        )

    if not isinstance(device_id, str) or not device_id.strip():
        raise CryptoPreconditionError("device_id must be a non-empty string")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise CryptoPreconditionError("flow_id must be a non-empty string")
    if not isinstance(sensitivity, str) or not sensitivity.strip():
        raise CryptoPreconditionError("sensitivity must be a non-empty string")
    if type(policy_version) is not int or policy_version < 1:
        raise CryptoPreconditionError("policy_version must be an integer >= 1 (not bool)")

    # Device and gateway independently create ephemeral X25519 keypairs.
    device_public, device_private = generate_keypair()
    gateway_public, gateway_private = generate_keypair()

    # Each side computes ECDH using its private key and the peer's public key.
    device_secret = derive_shared_secret(device_private, gateway_public)
    gateway_secret = derive_shared_secret(gateway_private, device_public)
    if not hmac.compare_digest(device_secret, gateway_secret):
        raise CryptoPreconditionError("X25519 shared-secret agreement failed")

    normalized_sensitivity = sensitivity.strip().upper()
    normalized_device_id = device_id.strip()
    normalized_flow_id = flow_id.strip()
    session_key = derive_session_key(
        device_secret,
        device_id=normalized_device_id,
        flow_id=normalized_flow_id,
        sensitivity_tier=normalized_sensitivity,
        policy_version=policy_version,
    )
    context = MessageContext(
        device_id=normalized_device_id,
        flow_id=normalized_flow_id,
        sensitivity_tier=normalized_sensitivity,
        policy_version=policy_version,
    )

    return ClassicalCryptoSession(
        device_id=normalized_device_id,
        flow_id=normalized_flow_id,
        sensitivity=normalized_sensitivity,
        policy_version=policy_version,
        mode="CLASSICAL",
        key_exchange="X25519",
        device_public_key=device_public,
        gateway_public_key=gateway_public,
        _encryptor=MessageEncryptor(session_key, context),
        _decryptor=MessageDecryptor(session_key, context),
    )
