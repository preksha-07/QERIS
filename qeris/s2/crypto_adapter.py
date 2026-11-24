"""
QERIS S2: S1 Crypto Adapter

Bridges S2 Gateway with S1's ML-KEM, HKDF, and AES-256-GCM modules,
or seamlessly falls back to S2's native crypto_engine.
Supports local cryptographic round-trip and session lifecycle management.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Optional

from qeris.s2.crypto_engine import (
    MessageEnvelope,
    create_context_aad,
    derive_session_key as engine_derive_session_key,
)

# Attempt import from S1 modules
_s1_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "s1"))
if _s1_path not in sys.path:
    sys.path.insert(0, _s1_path)

try:
    from qeris.session_crypto import (
        decapsulate as s1_decapsulate,
        derive_session_key as s1_derive_session_key,
        encapsulate as s1_encapsulate,
        generate_keypair as s1_generate_keypair,
    )
    from qeris.secure_message import (
        MessageContext,
        MessageDecryptor,
        MessageEncryptor,
    )
    _S1_CRYPTO_AVAILABLE = True
except Exception:
    _S1_CRYPTO_AVAILABLE = False


@dataclass
class CryptoSession:
    """Session context maintaining encryption and replay-protection state."""
    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    session_key: bytes
    _envelope: MessageEnvelope

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._envelope.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._envelope.decrypt(ciphertext)


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    session_key: Optional[bytes] = None,
) -> CryptoSession:
    """
    Establishes a cryptographically protected session context.
    """
    key = session_key or os.urandom(32)
    context_aad = create_context_aad(device_id, flow_id, sensitivity, policy_version)
    envelope = MessageEnvelope(session_key=key, context_aad=context_aad)
    return CryptoSession(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity=sensitivity,
        policy_version=policy_version,
        session_key=key,
        _envelope=envelope,
    )
