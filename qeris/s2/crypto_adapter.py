"""
QERIS S2: S1 Crypto Adapter
Milestone: S1 + S2 + S3 Integration

Bridges S2 Gateway with S1's Classical (X25519), PQC (ML-KEM-512), and Hybrid (X25519 + ML-KEM-768)
session crypto implementations, HKDF key derivation, and context-bound AES-256-GCM message protection.
Maintains dual compatibility with both S1 (QMSG) and S2 (QRS1) wire envelopes.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Optional, Tuple, Union

# Ensure S1, S2, and workspace root are in sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.abspath(os.path.join(_cur_dir, "..", ".."))
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

import qeris
_s1_pkg = os.path.join(_root_dir, "qeris", "s1", "qeris")
if os.path.isdir(_s1_pkg) and _s1_pkg not in getattr(qeris, "__path__", []):
    qeris.__path__.append(_s1_pkg)

# S2 Native Crypto Engine components
from qeris.s2.crypto_engine import (
    MessageEnvelope as S2MessageEnvelope,
    create_context_aad as s2_create_context_aad,
    derive_session_key as engine_derive_session_key,
)

# S1 PQC Session Crypto & Secure Message
try:
    from qeris.session_crypto import (
        decapsulate as s1_pqc_decapsulate,
        derive_session_key as s1_derive_session_key,
        encapsulate as s1_pqc_encapsulate,
        generate_keypair as s1_pqc_generate_keypair,
        compute_handshake_id as s1_pqc_handshake_id,
        CryptoInputError as S1CryptoInputError,
    )
    from qeris.secure_message import (
        AuthenticationError as S1AuthenticationError,
        MessageContext as S1MessageContext,
        MessageDecryptor as S1MessageDecryptor,
        MessageEncryptor as S1MessageEncryptor,
        ReplayError as S1ReplayError,
    )
    _S1_CRYPTO_AVAILABLE = True
except Exception:
    _S1_CRYPTO_AVAILABLE = False
    S1AuthenticationError = ValueError  # type: ignore
    S1ReplayError = ValueError  # type: ignore

# S1 Classical (X25519)
try:
    import qeris_classical.session_crypto as classical_crypto
    _CLASSICAL_AVAILABLE = True
except Exception:
    _CLASSICAL_AVAILABLE = False

# S1 Hybrid (X25519 + ML-KEM-768)
try:
    from qeris.hybrid_session_crypto import (
        generate_hybrid_keypair as s1_generate_hybrid_keypair,
        hybrid_encapsulate as s1_hybrid_encapsulate,
        hybrid_decapsulate as s1_hybrid_decapsulate,
        derive_hybrid_session_key as s1_derive_hybrid_session_key,
        compute_hybrid_handshake_id as s1_compute_hybrid_handshake_id,
    )
    _HYBRID_AVAILABLE = True
except Exception:
    _HYBRID_AVAILABLE = False


@dataclass
class CryptoSession:
    """Session context maintaining encryption, decryption, and replay-protection state."""
    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    session_key: bytes
    handshake_id: Optional[str] = None
    mode: str = "PQC"
    _s1_encryptor: Optional[Any] = None
    _s1_decryptor: Optional[Any] = None
    _s2_envelope: Optional[S2MessageEnvelope] = None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext using S1 MessageEncryptor (preferred) or S2 MessageEnvelope."""
        if self._s1_encryptor is not None:
            return self._s1_encryptor.encrypt(plaintext)
        if self._s2_envelope is not None:
            return self._s2_envelope.encrypt(plaintext)
        raise RuntimeError("No active encryption engine available on session")

    def decrypt(self, envelope_bytes: bytes) -> bytes:
        """
        Decrypts envelope bytes.
        Automatically detects S1 wire format (b'QMSG') or S2 wire format (b'QRS1').
        """
        if envelope_bytes.startswith(b"QMSG") and self._s1_decryptor is not None:
            return self._s1_decryptor.decrypt(envelope_bytes)
        elif envelope_bytes.startswith(b"QRS1") and self._s2_envelope is not None:
            return self._s2_envelope.decrypt(envelope_bytes)

        # Fallback trial
        if self._s1_decryptor is not None:
            try:
                return self._s1_decryptor.decrypt(envelope_bytes)
            except Exception:
                if self._s2_envelope is not None:
                    return self._s2_envelope.decrypt(envelope_bytes)
                raise
        if self._s2_envelope is not None:
            return self._s2_envelope.decrypt(envelope_bytes)

        raise RuntimeError("No active decryption engine available on session")


def perform_kem_exchange(
    mode: str,
    device_id: str = "dev-sim",
    flow_id: str = "flow-sim",
    sensitivity: str = "HIGH",
    policy_version: int = 1,
) -> Tuple[bytes, str]:
    """
    Simulates a full KEM exchange (client & server) using authentic S1 cryptographic primitives.
    Returns: (session_key: bytes, handshake_id: str)
    """
    import hashlib
    mode_upper = mode.upper()
    if mode_upper == "CLASSICAL" and _CLASSICAL_AVAILABLE:
        client_pub, client_priv = classical_crypto.generate_keypair()
        server_pub, server_priv = classical_crypto.generate_keypair()
        ss = classical_crypto.derive_shared_secret(server_priv, client_pub)
        hid = hashlib.sha256(b"QERIS-CLASSICAL-HANDSHAKE-v1\x00" + client_pub + server_pub).hexdigest()
        key = classical_crypto.derive_session_key(
            ss,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity,
            policy_version=policy_version,
        )
        return key, hid

    elif mode_upper == "HYBRID" and _HYBRID_AVAILABLE:
        client_kp = s1_generate_hybrid_keypair()
        ct, server_ss = s1_hybrid_encapsulate(client_kp.public_key_bytes)
        client_ss = s1_hybrid_decapsulate(ct, client_kp.private_key_bytes)
        assert server_ss == client_ss, "Hybrid shared secret mismatch"
        hid = s1_compute_hybrid_handshake_id(
            client_kp.public_key_bytes,
            ct,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity,
            policy_version=policy_version,
        )
        key = s1_derive_hybrid_session_key(
            server_ss,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity,
            policy_version=policy_version,
            handshake_id=hid,
        )
        return key, hid

    elif mode_upper in ("PQC", "PQ") and _S1_CRYPTO_AVAILABLE:
        client_pub, client_priv = s1_pqc_generate_keypair()
        ct, server_ss = s1_pqc_encapsulate(client_pub)
        client_ss = s1_pqc_decapsulate(ct, client_priv)
        assert server_ss == client_ss, "PQC shared secret mismatch"
        hid = s1_pqc_handshake_id(
            client_pub,
            ct,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity,
            policy_version=policy_version,
        )
        key = s1_derive_session_key(
            server_ss,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity,
            policy_version=policy_version,
        )
        return key, hid

    # Fallback to random key if cryptographic primitives are unavailable
    rand_key = os.urandom(32)
    rand_hid = os.urandom(32).hex()
    return rand_key, rand_hid


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    session_key: Optional[bytes] = None,
    mode: str = "PQC",
    handshake_id: Optional[str] = None,
) -> CryptoSession:
    """
    Establishes a cryptographically protected session context.
    Binds both S1 MessageEncryptor/Decryptor (context-bound) and S2 MessageEnvelope.
    """
    if session_key is None:
        key, hid = perform_kem_exchange(
            mode=mode,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity=sensitivity,
            policy_version=policy_version,
        )
        if handshake_id is None:
            handshake_id = hid
    else:
        key = session_key

    s1_enc = None
    s1_dec = None
    if _S1_CRYPTO_AVAILABLE:
        try:
            s1_ctx = S1MessageContext(
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity,
                policy_version=policy_version,
            )
            s1_enc = S1MessageEncryptor(session_key=key, context=s1_ctx)
            s1_dec = S1MessageDecryptor(session_key=key, context=s1_ctx)
        except Exception:
            s1_enc = None
            s1_dec = None

    s2_context_aad = s2_create_context_aad(device_id, flow_id, sensitivity, policy_version)
    s2_env = S2MessageEnvelope(session_key=key, context_aad=s2_context_aad)

    return CryptoSession(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity=sensitivity,
        policy_version=policy_version,
        session_key=key,
        handshake_id=handshake_id,
        mode=mode,
        _s1_encryptor=s1_enc,
        _s1_decryptor=s1_dec,
        _s2_envelope=s2_env,
    )
