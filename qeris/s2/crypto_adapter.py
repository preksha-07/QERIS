"""
S2-S1 Cryptographic Adapter (Updated for QERIS Integration)

Connects the S2 Security Gateway directly to S1 Post-Quantum Cryptographic Modules:
- ML-KEM-512 (FIPS 203 key encapsulation)
- HKDF-SHA256 (RFC 5869 context-bound key derivation)
- AES-256-GCM (NIST SP 800-38D authenticated payload encryption)

Important Architectural Clarifications:
- This adapter executes a verified local cryptographic round-trip session between emulated
  sender and receiver endpoints. It is NOT a remote network device-to-gateway transport protocol.
- Only the post-quantum mode ('PQC' / 'PQ') is cryptographically implemented.
- 'CLASSICAL' and 'HYBRID' cryptographic handshakes are explicitly NOT implemented in this prototype;
  any attempt to establish a session under those modes raises UnsupportedCryptoModeError.
- Cryptographic material (private keys, shared secrets, session keys, raw plaintext) is NEVER logged.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Any, Final, Optional

# Ensure S1 is on sys.path
_S2_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _S2_DIR.parent.parent
_S1_DIR = _REPO_ROOT / "qeris" / "s1"
if str(_S1_DIR) not in sys.path:
    sys.path.insert(0, str(_S1_DIR))

try:
    from qeris.session_crypto import (
        CIPHERTEXT_LENGTH,
        PUBLIC_KEY_LENGTH,
        SECRET_KEY_LENGTH,
        SHARED_SECRET_LENGTH,
        decapsulate,
        derive_session_key,
        encapsulate,
        generate_keypair,
    )
    from qeris.secure_message import (
        MAX_ENVELOPE_SIZE,
        MessageContext,
        MessageDecryptor,
        MessageEncryptor,
    )
    _CRYPTO_AVAILABLE = True
except ImportError as err:
    _CRYPTO_AVAILABLE = False
    _IMPORT_ERROR = str(err)


class UnsupportedCryptoModeError(NotImplementedError):
    """Raised when attempting to establish a cryptographic session with an unimplemented mode."""


class CryptoPreconditionError(RuntimeError):
    """Raised when policy, context, or key establishment preconditions are violated."""


@dataclass
class CryptoSession:
    """Manages persistent authenticated encryption and monotonic replay state for a verified flow session."""

    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    mode: str
    _encryptor: MessageEncryptor
    _decryptor: MessageDecryptor
    kem_ciphertext: bytes = b""

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt application payload using the session's monotonic GCM nonce counter."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")
        return self._encryptor.encrypt(bytes(plaintext))

    def decrypt(self, envelope: bytes) -> bytes:
        """Decrypt and authenticate payload envelope, strictly rejecting replayed nonces."""
        if not isinstance(envelope, (bytes, bytearray)):
            raise TypeError(f"Envelope must be bytes, got {type(envelope).__name__}")
        return self._decryptor.decrypt(bytes(envelope))


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    mode: str = "PQC",
) -> CryptoSession:
    """Establishes an authenticated cryptographic session bound to the verified policy context.

    Preconditions:
    1. S1 cryptographic dependencies (liboqs, cryptography) must be available.
    2. Requested mode must be 'PQC' or 'PQ'. CLASSICAL and HYBRID modes are explicitly unsupported.
    3. Context parameters must be non-empty and well-formed.

    Cryptographic Steps:
    1. Receiver generates fresh ML-KEM-512 keypair (public_key, secret_key).
    2. Sender encapsulates against public_key -> (ciphertext, sender_shared_secret).
    3. Receiver decapsulates ciphertext using secret_key -> receiver_shared_secret.
    4. Confirms sender_shared_secret == receiver_shared_secret.
    5. Derives 32-byte session key using HKDF-SHA256 bound to (device_id, flow_id, sensitivity, policy_version).
    6. Creates MessageEncryptor (sender) and MessageDecryptor (receiver) bound to authenticated AAD context.
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(f"S1 cryptography module is unavailable: {_IMPORT_ERROR}")

    normalized_mode = mode.strip().upper()
    if normalized_mode not in ("PQC", "PQ"):
        raise UnsupportedCryptoModeError(
            f"Cryptographic session establishment is only implemented for mode 'PQC' (ML-KEM-512 + HKDF-SHA256 + AES-256-GCM). "
            f"Mode '{mode}' has no cryptographic implementation in this gateway prototype."
        )

    # Validate context parameters
    if not isinstance(device_id, str) or not device_id.strip():
        raise CryptoPreconditionError("device_id must be a non-empty string")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise CryptoPreconditionError("flow_id must be a non-empty string")
    if not isinstance(sensitivity, str) or not sensitivity.strip():
        raise CryptoPreconditionError("sensitivity must be a non-empty string")
    if type(policy_version) is not int or isinstance(policy_version, bool) or policy_version < 1:
        raise CryptoPreconditionError(f"policy_version must be an integer >= 1, got {policy_version!r}")

    # 1. Receiver generates fresh ML-KEM-512 keypair
    receiver_pub, receiver_sec = generate_keypair()

    # 2. Sender encapsulates to receiver's public key
    kem_ciphertext, sender_secret = encapsulate(receiver_pub)

    # 3. Receiver decapsulates ciphertext with secret key
    receiver_secret = decapsulate(kem_ciphertext, receiver_sec)

    # 4. Confirm shared secret agreement
    if sender_secret != receiver_secret:
        raise CryptoPreconditionError("ML-KEM-512 shared secret agreement failure between sender and receiver")

    # 5. HKDF-SHA256 context-bound session key derivation
    session_key = derive_session_key(
        shared_secret=sender_secret,
        device_id=device_id.strip(),
        flow_id=flow_id.strip(),
        sensitivity_tier=sensitivity.strip().upper(),
        policy_version=policy_version,
    )

    # 6. Bind AAD context to messages
    context = MessageContext(
        device_id=device_id.strip(),
        flow_id=flow_id.strip(),
        sensitivity_tier=sensitivity.strip().upper(),
        policy_version=policy_version,
    )

    # 7. Create encryptor and decryptor with persistent monotonic counter state
    encryptor = MessageEncryptor(session_key, context)
    decryptor = MessageDecryptor(session_key, context)

    return CryptoSession(
        device_id=device_id.strip(),
        flow_id=flow_id.strip(),
        sensitivity=sensitivity.strip().upper(),
        policy_version=policy_version,
        mode=normalized_mode,
        _encryptor=encryptor,
        _decryptor=decryptor,
        kem_ciphertext=kem_ciphertext,
    )
