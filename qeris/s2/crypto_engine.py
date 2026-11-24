"""
QERIS S2: Cryptographic Engine

Integrates NIST FIPS 204 ML-DSA-65 post-quantum digital signatures,
FIPS 203 ML-KEM session establishment, HKDF-SHA256 key derivation,
and AES-256-GCM authenticated message encryption with context binding.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Any, Final, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qeris.s2.config import DEFAULT_SIG_ALG

# ML-DSA-65 FIPS 204 Standard Sizes
ML_DSA_65_PUBLIC_KEY_SIZE: Final[int] = 1952
ML_DSA_65_SIGNATURE_SIZE: Final[int] = 3309
ML_DSA_65_SECRET_KEY_SIZE: Final[int] = 4032

# HKDF Constants
HKDF_SALT: Final[bytes] = b"QERIS-HKDF-SHA256-SALT-v1"
HKDF_LABEL: Final[bytes] = b"QERIS-SESSION-KEY-v1"
SESSION_KEY_LENGTH: Final[int] = 32

# AES-GCM Wire Envelope
ENVELOPE_MAGIC: Final[bytes] = b"QMSG"
ENVELOPE_VERSION: Final[int] = 1
ENVELOPE_HEADER_FORMAT: Final[str] = ">4sBQ"  # magic (4), version (1), counter (8)
ENVELOPE_HEADER_SIZE: Final[int] = struct.calcsize(ENVELOPE_HEADER_FORMAT)  # 13 bytes


class CryptoError(Exception):
    """Base exception for crypto engine failures."""
    pass


class SignatureVerificationError(CryptoError):
    """Raised when policy signature verification fails."""
    pass


class AuthenticationError(CryptoError):
    """Raised when AEAD authentication tag or context fails."""
    pass


class ReplayError(CryptoError):
    """Raised when message counter is stale or replayed."""
    pass


# ---------------------------------------------------------------------------
# ML-DSA-65 Authority Key Management & Verification
# ---------------------------------------------------------------------------

def generate_authority_keypair() -> tuple[bytes, bytes, str]:
    """
    Generates a new FIPS 204 ML-DSA-65 keypair.
    Returns:
        (private_key_pem: bytes, public_key_pem: bytes, public_key_hex: str)
    """
    priv = mldsa.MLDSA65PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_hex = pub.public_bytes_raw().hex()
    return priv_pem, pub_pem, pub_hex


def load_authority_public_key(key_material: Union[bytes, str]) -> mldsa.MLDSA65PublicKey:
    """
    Loads an ML-DSA-65 public key from PEM bytes, PEM string, raw bytes, or hex string.
    """
    if isinstance(key_material, str):
        key_str = key_material.strip()
        if key_str.startswith("-----BEGIN"):
            return serialization.load_pem_public_key(key_str.encode("utf-8"))
        try:
            raw_bytes = bytes.fromhex(key_str)
            return mldsa.MLDSA65PublicKey.from_public_bytes(raw_bytes)
        except Exception as exc:
            raise CryptoError(f"Failed to parse public key hex: {exc}") from exc

    if isinstance(key_material, (bytes, bytearray)):
        b = bytes(key_material).strip()
        if b.startswith(b"-----BEGIN"):
            return serialization.load_pem_public_key(b)
        if len(b) == ML_DSA_65_PUBLIC_KEY_SIZE:
            return mldsa.MLDSA65PublicKey.from_public_bytes(b)
        # Try hex decode if length doesn't match raw
        try:
            raw_bytes = bytes.fromhex(b.decode("ascii"))
            return mldsa.MLDSA65PublicKey.from_public_bytes(raw_bytes)
        except Exception:
            pass

    raise CryptoError(f"Unsupported public key material format or length: {type(key_material)}")


def load_authority_private_key(key_material: Union[bytes, str]) -> mldsa.MLDSA65PrivateKey:
    """
    Loads an ML-DSA-65 private key from PEM bytes or PEM string.
    """
    if isinstance(key_material, str):
        key_material = key_material.encode("utf-8")
    return serialization.load_pem_private_key(key_material, password=None)


def sign_canonical_policy(
    canonical_bytes: bytes,
    private_key_material: Union[bytes, str, mldsa.MLDSA65PrivateKey],
) -> str:
    """
    Signs canonical policy bytes using ML-DSA-65.
    Returns signature as a hex string.
    """
    if isinstance(private_key_material, mldsa.MLDSA65PrivateKey):
        priv = private_key_material
    else:
        priv = load_authority_private_key(private_key_material)
    sig_bytes = priv.sign(canonical_bytes)
    return sig_bytes.hex()


def verify_policy_signature(
    canonical_bytes: bytes,
    signature_hex: str,
    public_key_material: Union[bytes, str, mldsa.MLDSA65PublicKey],
) -> bool:
    """
    Verifies an ML-DSA-65 signature over canonical policy bytes.
    Returns True if valid, False if invalid or tampered.
    """
    try:
        if isinstance(public_key_material, mldsa.MLDSA65PublicKey):
            pub = public_key_material
        else:
            pub = load_authority_public_key(public_key_material)
        sig_bytes = bytes.fromhex(signature_hex.strip())
        pub.verify(sig_bytes, canonical_bytes)
        return True
    except (InvalidSignature, ValueError, CryptoError):
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session Crypto: KEM, KDF & Context-Bound Message Protection
# ---------------------------------------------------------------------------

def derive_session_key(
    shared_secret: bytes,
    *,
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
) -> bytes:
    """
    Derives a 32-byte session key using HKDF-SHA256 with length-prefixed context binding.
    """
    if len(shared_secret) < 16:
        raise CryptoError("Shared secret must be at least 16 bytes")

    context = struct.pack(
        ">H%dsH%dsH%dsQ" % (len(device_id), len(flow_id), len(sensitivity)),
        len(device_id), device_id.encode("utf-8"),
        len(flow_id), flow_id.encode("utf-8"),
        len(sensitivity), sensitivity.encode("utf-8"),
        policy_version,
    )

    # HKDF-Extract: PRK = HMAC-SHA256(HKDF_SALT, shared_secret)
    prk = hmac.new(HKDF_SALT, shared_secret, hashlib.sha256).digest()

    # HKDF-Expand: OKM = HMAC-SHA256(PRK, HKDF_LABEL + context + 0x01)
    info = HKDF_LABEL + context + b"\x01"
    okm = hmac.new(prk, info, hashlib.sha256).digest()
    return okm[:SESSION_KEY_LENGTH]


def create_context_aad(
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
) -> bytes:
    """Creates Associated Authenticated Data (AAD) for AES-256-GCM envelope."""
    return struct.pack(
        ">H%dsH%dsH%dsQ" % (len(device_id), len(flow_id), len(sensitivity)),
        len(device_id), device_id.encode("utf-8"),
        len(flow_id), flow_id.encode("utf-8"),
        len(sensitivity), sensitivity.encode("utf-8"),
        policy_version,
    )


class MessageEnvelope:
    """
    Encrypts and decrypts telemetry payloads using AES-256-GCM with
    authenticated context binding and strictly increasing counter replay protection.
    """

    def __init__(self, session_key: bytes, context_aad: bytes):
        if len(session_key) != 32:
            raise CryptoError("Session key must be 32 bytes for AES-256-GCM")
        self._aead = AESGCM(session_key)
        self._context_aad = context_aad
        self._send_counter: int = 0
        self._last_received_counter: int = -1

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext and returns self-describing wire envelope."""
        self._send_counter += 1
        counter = self._send_counter

        # 96-bit nonce: 4 bytes zero + 8 bytes counter (big-endian)
        nonce = b"\x00\x00\x00\x00" + struct.pack(">Q", counter)
        header = struct.pack(ENVELOPE_HEADER_FORMAT, ENVELOPE_MAGIC, ENVELOPE_VERSION, counter)
        full_aad = header + self._context_aad

        ciphertext_and_tag = self._aead.encrypt(nonce, plaintext, full_aad)
        return header + ciphertext_and_tag

    def decrypt(self, envelope: bytes) -> bytes:
        """Decrypts envelope and verifies integrity, AAD, and counter freshness."""
        if len(envelope) < ENVELOPE_HEADER_SIZE + 16:
            raise CryptoError("Envelope is truncated")

        header = envelope[:ENVELOPE_HEADER_SIZE]
        magic, version, counter = struct.unpack(ENVELOPE_HEADER_FORMAT, header)

        if magic != ENVELOPE_MAGIC:
            raise CryptoError("Invalid envelope magic bytes")
        if version != ENVELOPE_VERSION:
            raise CryptoError("Unsupported envelope version")
        if counter <= self._last_received_counter:
            raise ReplayError(
                f"Replayed or out-of-order counter {counter} <= {self._last_received_counter}"
            )

        nonce = b"\x00\x00\x00\x00" + struct.pack(">Q", counter)
        ciphertext_and_tag = envelope[ENVELOPE_HEADER_SIZE:]
        full_aad = header + self._context_aad

        try:
            plaintext = self._aead.decrypt(nonce, ciphertext_and_tag, full_aad)
            self._last_received_counter = counter
            return plaintext
        except InvalidTag as exc:
            raise AuthenticationError("AEAD message authentication tag invalid") from exc


# ---------------------------------------------------------------------------
# High-Level Helper Functions (KEM & Message AEAD)
# ---------------------------------------------------------------------------

def generate_kem_keypair(alg_name: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """
    Generates an ML-KEM keypair.
    Returns (public_key_raw_bytes, private_key_raw_bytes).
    """
    if "1024" in alg_name:
        priv = mlkem.MLKEM1024PrivateKey.generate()
    else:
        priv = mlkem.MLKEM768PrivateKey.generate()
    pub = priv.public_key()
    return pub.public_bytes_raw(), priv.private_bytes_raw()


def encapsulate(public_key_bytes: bytes, alg_name: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """
    Encapsulates a shared secret against the recipient's ML-KEM public key.
    Returns (ciphertext_bytes, shared_secret_32_bytes).
    """
    if "1024" in alg_name:
        pub = mlkem.MLKEM1024PublicKey.from_public_bytes(public_key_bytes)
    else:
        pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_key_bytes)
    shared_secret, ciphertext = pub.encapsulate()
    return ciphertext, shared_secret


def decapsulate(ciphertext: bytes, private_key_bytes: bytes, alg_name: str = "ML-KEM-768") -> bytes:
    """
    Decapsulates the ciphertext using recipient's ML-KEM private key.
    Returns shared_secret_32_bytes.
    """
    if "1024" in alg_name:
        priv = mlkem.MLKEM1024PrivateKey.from_seed_bytes(private_key_bytes)
    else:
        priv = mlkem.MLKEM768PrivateKey.from_seed_bytes(private_key_bytes)
    try:
        return priv.decapsulate(ciphertext)
    except Exception as exc:
        raise CryptoError(f"KEM decapsulation failed: {exc}") from exc


def encrypt_message(
    plaintext: bytes,
    key: bytes,
    device_id: str,
    flow_id: str,
    sensitivity: str,
    policy_version: int,
    counter: int = 1,
) -> bytes:
    """Encrypts plaintext with context-bound AAD and monotonic counter."""
    aad = create_context_aad(device_id, flow_id, sensitivity, policy_version)
    env = MessageEnvelope(key, aad)
    env._send_counter = counter - 1
    return env.encrypt(plaintext)


def decrypt_message(
    envelope_bytes: bytes,
    key: bytes,
    expected_device_id: str,
    expected_flow_id: str,
    expected_sensitivity: str,
    expected_policy_version: int,
    last_seen_counter: int = -1,
) -> bytes:
    """Decrypts envelope and verifies AAD context and counter freshness."""
    aad = create_context_aad(expected_device_id, expected_flow_id, expected_sensitivity, expected_policy_version)
    env = MessageEnvelope(key, aad)
    env._last_received_counter = last_seen_counter
    return env.decrypt(envelope_bytes)

