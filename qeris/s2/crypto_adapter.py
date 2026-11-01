"""
S2 Cryptographic Adapter (Dual-Mode: Post-Quantum + Classical)

Connects the S2 Security Gateway to cryptographic session implementations:
1. Post-Quantum Mode ('PQC' / 'PQ'):
   - ML-KEM-512 (FIPS 203 key encapsulation mechanism)
   - HKDF-SHA256 (RFC 5869 context-bound key derivation)
   - AES-256-GCM (NIST SP 800-38D authenticated message encryption)
2. Classical Mode ('CLASSICAL'):
   - X25519 (RFC 7748 ephemeral Diffie–Hellman key agreement via qeris_classical)
   - HKDF-SHA256 (RFC 5869 context-bound key derivation)
   - AES-256-GCM (NIST SP 800-38D authenticated message encryption)

Important Architectural Clarifications:
- This adapter executes verified local cryptographic round-trip sessions between emulated
  sender and receiver endpoints. It is a local session demonstration, NOT a remote network transport protocol.
- Both PQC and CLASSICAL derive context-bound keys using HKDF-SHA256 and encrypt payloads using the
  same QMSG v1 envelope, monotonic 96-bit counter nonce, and authenticated associated data (AAD).
- 'HYBRID' mode is explicitly NOT implemented in this prototype; any attempt to establish a session
  under HYBRID raises UnsupportedCryptoModeError.
- X25519 key agreement alone does not authenticate the communicating peer. In this local demonstration,
  keys are generated ephemerally; a production network deployment must bind and authenticate keys to peer identities.
- Cryptographic material (private keys, shared secrets, session keys, raw plaintext) is NEVER logged.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Any, Final, Optional, Union

# Ensure S1 and repo root are on sys.path
_S2_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _S2_DIR.parent.parent
_S1_DIR = _REPO_ROOT / "qeris" / "s1"

for p in (str(_REPO_ROOT), str(_S1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# PQC Cryptographic Modules (S1)
try:
    from qeris.session_crypto import (
        CIPHERTEXT_LENGTH,
        PUBLIC_KEY_LENGTH,
        SECRET_KEY_LENGTH,
        SHARED_SECRET_LENGTH,
        decapsulate,
        derive_session_key as pqc_derive_session_key,
        encapsulate,
        generate_keypair as pqc_generate_keypair,
    )
    from qeris.secure_message import (
        MAX_ENVELOPE_SIZE,
        MessageContext as PQCMessageContext,
        MessageDecryptor as PQCMessageDecryptor,
        MessageEncryptor as PQCMessageEncryptor,
    )
    _PQC_CRYPTO_AVAILABLE = True
except ImportError as err:
    _PQC_CRYPTO_AVAILABLE = False
    _PQC_IMPORT_ERROR = str(err)

# Classical Cryptographic Modules (qeris_classical)
try:
    from qeris_classical.adapter import (
        ClassicalCryptoSession,
        CryptoPreconditionError as ClassicalPreconditionError,
        UnsupportedCryptoModeError as ClassicalUnsupportedModeError,
        establish_session as establish_classical_session,
    )
    _CLASSICAL_AVAILABLE = True
except ImportError as err:
    _CLASSICAL_AVAILABLE = False
    _CLASSICAL_IMPORT_ERROR = str(err)


class UnsupportedCryptoModeError(NotImplementedError):
    """Raised when attempting to establish a cryptographic session with an unimplemented or unsupported mode."""


class CryptoPreconditionError(RuntimeError):
    """Raised when policy, context, or key establishment preconditions are violated."""


@dataclass
class CryptoSession:
    """Manages persistent authenticated encryption and monotonic replay state for a verified PQC flow session."""

    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    mode: str
    _encryptor: PQCMessageEncryptor
    _decryptor: PQCMessageDecryptor
    kem_ciphertext: bytes = b""
    key_exchange: str = "ML-KEM-512"

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


# Type alias for any supported active session
SessionType = Union[CryptoSession, ClassicalCryptoSession]


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    mode: str = "PQC",
) -> SessionType:
    """Establishes an authenticated cryptographic session bound to the verified policy context.

    Dispatches to the appropriate cryptographic implementation based on the requested mode:
    - 'PQC' or 'PQ': executes S1 ML-KEM-512 key agreement and AES-256-GCM.
    - 'CLASSICAL': executes qeris_classical X25519 key agreement and AES-256-GCM.
    - 'HYBRID': raises UnsupportedCryptoModeError (explicitly unsupported in this gateway).
    - Any other mode: raises UnsupportedCryptoModeError.

    Preconditions:
    1. Dependencies for the requested mode must be available.
    2. Context parameters must be non-empty and well-formed.
    """
    if not isinstance(mode, str):
        raise CryptoPreconditionError("mode must be a string")

    normalized_mode = mode.strip().upper()

    # Reject HYBRID explicitly
    if normalized_mode == "HYBRID":
        raise UnsupportedCryptoModeError(
            "Mode 'HYBRID' is explicitly unsupported in this gateway prototype. "
            "Supported cryptographic modes are 'PQC' and 'CLASSICAL'."
        )

    # Validate common context parameters
    if not isinstance(device_id, str) or not device_id.strip():
        raise CryptoPreconditionError("device_id must be a non-empty string")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise CryptoPreconditionError("flow_id must be a non-empty string")
    if not isinstance(sensitivity, str) or not sensitivity.strip():
        raise CryptoPreconditionError("sensitivity must be a non-empty string")
    if type(policy_version) is not int or isinstance(policy_version, bool) or policy_version < 1:
        raise CryptoPreconditionError(f"policy_version must be an integer >= 1, got {policy_version!r}")

    # --- Mode 1: Post-Quantum Cryptography (ML-KEM-512) ---
    if normalized_mode in ("PQC", "PQ"):
        if not _PQC_CRYPTO_AVAILABLE:
            raise RuntimeError(f"S1 post-quantum cryptography module is unavailable: {_PQC_IMPORT_ERROR}")

        # 1. Receiver generates fresh ML-KEM-512 keypair
        receiver_pub, receiver_sec = pqc_generate_keypair()

        # 2. Sender encapsulates to receiver's public key
        kem_ciphertext, sender_secret = encapsulate(receiver_pub)

        # 3. Receiver decapsulates ciphertext with secret key
        receiver_secret = decapsulate(kem_ciphertext, receiver_sec)

        # 4. Confirm shared secret agreement
        if sender_secret != receiver_secret:
            raise CryptoPreconditionError("ML-KEM-512 shared secret agreement failure between sender and receiver")

        # 5. HKDF-SHA256 context-bound session key derivation
        session_key = pqc_derive_session_key(
            shared_secret=sender_secret,
            device_id=device_id.strip(),
            flow_id=flow_id.strip(),
            sensitivity_tier=sensitivity.strip().upper(),
            policy_version=policy_version,
        )

        # 6. Bind AAD context to messages
        context = PQCMessageContext(
            device_id=device_id.strip(),
            flow_id=flow_id.strip(),
            sensitivity_tier=sensitivity.strip().upper(),
            policy_version=policy_version,
        )

        # 7. Create encryptor and decryptor with persistent monotonic counter state
        encryptor = PQCMessageEncryptor(session_key, context)
        decryptor = PQCMessageDecryptor(session_key, context)

        return CryptoSession(
            device_id=device_id.strip(),
            flow_id=flow_id.strip(),
            sensitivity=sensitivity.strip().upper(),
            policy_version=policy_version,
            mode=normalized_mode,
            key_exchange="ML-KEM-512",
            _encryptor=encryptor,
            _decryptor=decryptor,
            kem_ciphertext=kem_ciphertext,
        )

    # --- Mode 2: Classical Cryptography (X25519) ---
    elif normalized_mode == "CLASSICAL":
        if not _CLASSICAL_AVAILABLE:
            raise RuntimeError(f"Classical cryptography module is unavailable: {_CLASSICAL_IMPORT_ERROR}")

        try:
            return establish_classical_session(
                device_id=device_id.strip(),
                flow_id=flow_id.strip(),
                sensitivity=sensitivity.strip().upper(),
                policy_version=policy_version,
                mode="CLASSICAL",
            )
        except (ClassicalPreconditionError, ValueError) as err:
            raise CryptoPreconditionError(str(err)) from err

    # --- Unknown / Unsupported Mode ---
    else:
        raise UnsupportedCryptoModeError(
            f"Unsupported cryptographic mode: '{mode}'. Supported modes are 'PQC' and 'CLASSICAL'."
        )
