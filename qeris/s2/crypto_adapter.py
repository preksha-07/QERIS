"""
S2-S1 Crypto Adapter

Connects S2 to S1's ML-KEM, HKDF-SHA256 and AES-GCM modules.

This version supports a local cryptographic round-trip demonstration.
It is not yet the complete device-to-gateway handshake.
"""

from dataclasses import dataclass
import sys
import os

# Ensure S1 is on the path if needed
_s1_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "s1"))
if _s1_path not in sys.path:
    sys.path.insert(0, _s1_path)

try:
    from qeris.session_crypto import (
        generate_keypair,
        encapsulate,
        decapsulate,
        derive_session_key,
    )

    from qeris.secure_message import (
        MessageContext,
        MessageEncryptor,
        MessageDecryptor,
    )
    _CRYPTO_AVAILABLE = True
except Exception:
    _CRYPTO_AVAILABLE = False
    MessageEncryptor = object
    MessageDecryptor = object


@dataclass
class CryptoSession:
    """Keep encryption and replay-protection state for a demo session."""

    device_id: str
    flow_id: str
    sensitivity: str
    policy_version: int
    _encryptor: MessageEncryptor
    _decryptor: MessageDecryptor
    kem_ciphertext: bytes = b""

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt using the session's persistent encryptor."""
        return self._encryptor.encrypt(plaintext)

    def decrypt(self, envelope: bytes) -> bytes:
        """Decrypt using the session's persistent replay state."""
        return self._decryptor.decrypt(envelope)


def establish_session(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
) -> CryptoSession:
    """
    Demonstrate ML-KEM key agreement and create a persistent
    AES-GCM encryptor/decryptor pair.

    This is a local prototype demonstration, not the final
    device-to-gateway key-establishment protocol.
    """

    # 1. Generate an ML-KEM key pair.
    public_key, secret_key = generate_keypair()

    # 2. Encapsulate to the public key.
    ciphertext, sender_shared_secret = encapsulate(public_key)

    # 3. Decapsulate with the corresponding secret key.
    receiver_shared_secret = decapsulate(ciphertext, secret_key)

    # 4. Confirm that both sides recovered the same shared secret.
    if sender_shared_secret != receiver_shared_secret:
        raise RuntimeError("ML-KEM shared-secret mismatch")

    # 5. Derive a session key bound to the flow context.
    session_key = derive_session_key(
        sender_shared_secret,
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=sensitivity,
        policy_version=policy_version,
    )

    # 6. Bind messages to the same device/flow/policy context.
    context = MessageContext(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=sensitivity,
        policy_version=policy_version,
    )

    # 7. Create these objects once so their counter state is retained.
    encryptor = MessageEncryptor(session_key, context)
    decryptor = MessageDecryptor(session_key, context)

    return CryptoSession(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity=sensitivity,
        policy_version=policy_version,
        _encryptor=encryptor,
        _decryptor=decryptor,
        kem_ciphertext=ciphertext,
    )
