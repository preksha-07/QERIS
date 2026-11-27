"""QERIS S1: Ed25519 Device Authentication Module.

Implements long-term device authentication according to DEC-1 and the Master Blueprint:
- Long-term device credential enrollment (32-byte Ed25519 public key).
- Private key protection on the device (confidentiality: never in logs or exceptions).
- Canonical device-authentication message with domain separation b"QERIS-DEVICE-AUTH-v1".
- Binding to actual handshake context (device_id, handshake_id, challenge_nonce, timestamp).
- Gateway freshness challenge generation, expiry window, and single-use enforcement.
- Typed verification statuses and results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
import time
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# Domain separation tag for device authentication
DEVICE_AUTH_DOMAIN_SEPARATOR: bytes = b"QERIS-DEVICE-AUTH-v1\x00"
CHALLENGE_NONCE_LENGTH: int = 32  # 32 random bytes for freshness challenge
DEFAULT_CHALLENGE_TTL_SECONDS: float = 60.0  # 60 second validity window


class DeviceAuthStatus(str, Enum):
    """Typed verification statuses for device authentication attempts."""

    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_INVALID_SIGNATURE = "AUTH_INVALID_SIGNATURE"
    AUTH_UNKNOWN_DEVICE = "AUTH_UNKNOWN_DEVICE"
    AUTH_REVOKED = "AUTH_REVOKED"
    AUTH_CHALLENGE_EXPIRED = "AUTH_CHALLENGE_EXPIRED"
    AUTH_CHALLENGE_REPLAYED = "AUTH_CHALLENGE_REPLAYED"
    AUTH_MALFORMED = "AUTH_MALFORMED"


@dataclass(frozen=True)
class DeviceAuthResult:
    """Structured result of an authentication verification attempt."""

    status: DeviceAuthStatus
    device_id: str
    authenticated: bool
    error_detail: str = ""

    def __bool__(self) -> bool:
        return self.authenticated


class Ed25519DeviceCredential:
    """Manages an edge device's long-term Ed25519 authentication credential.

    Confidentiality guarantee:
    The private key is strictly isolated and never exposed in __repr__, __str__,
    or serialized payloads.
    """

    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None) -> None:
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            self._private_key = private_key
        else:
            raise TypeError("private_key must be an Ed25519PrivateKey instance")

        self._public_key = self._private_key.public_key()
        self._public_bytes = self._public_key.public_bytes_raw()

    @classmethod
    def from_private_bytes(cls, raw_bytes: bytes) -> "Ed25519DeviceCredential":
        """Instantiate credential from 32 raw private seed bytes."""
        if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) != 32:
            raise ValueError("Raw Ed25519 private key seed must be exactly 32 bytes")
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(raw_bytes))
        return cls(priv)

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw 32-byte Ed25519 public key."""
        return self._public_bytes

    @property
    def public_key_hex(self) -> str:
        """Return 64-character lowercase hex string of public key for enrollment."""
        return self._public_bytes.hex()

    def sign_authentication_message(
        self,
        *,
        device_id: str,
        handshake_id: str,
        challenge_nonce: bytes,
        timestamp: Optional[int] = None,
    ) -> bytes:
        """Create a canonical device-authentication signature over the handshake context."""
        canonical_msg = build_canonical_device_auth_message(
            device_id=device_id,
            handshake_id=handshake_id,
            challenge_nonce=challenge_nonce,
            timestamp=timestamp,
        )
        return self._private_key.sign(canonical_msg)

    def __repr__(self) -> str:
        # Strictly hide private key in string representations
        return f"<Ed25519DeviceCredential pub={self.public_key_hex[:12]}... (secret redacted)>"

    def __str__(self) -> str:
        return self.__repr__()


def build_canonical_device_auth_message(
    *,
    device_id: str,
    handshake_id: str,
    challenge_nonce: bytes,
    timestamp: Optional[int] = None,
) -> bytes:
    """Format the canonical, unambiguous device-authentication message.

    Encoding structure:
    - DOMAIN_SEPARATOR (length-prefixed)
    - device_id (length-prefixed UTF-8)
    - handshake_id (length-prefixed UTF-8 transcript hash)
    - challenge_nonce (length-prefixed bytes)
    - timestamp (8-byte big-endian uint64)
    """
    if not isinstance(device_id, str) or not device_id.strip():
        raise ValueError("device_id must be a non-empty string")
    if not isinstance(handshake_id, str) or not handshake_id.strip():
        raise ValueError("handshake_id must be a non-empty string")
    if len(handshake_id) != 64:
        raise ValueError("handshake_id must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(handshake_id)
    except ValueError as exc:
        raise ValueError("handshake_id must contain only hexadecimal characters") from exc
    if not isinstance(challenge_nonce, (bytes, bytearray)) or len(challenge_nonce) != CHALLENGE_NONCE_LENGTH:
        raise ValueError(f"challenge_nonce must be exactly {CHALLENGE_NONCE_LENGTH} bytes")

    if timestamp is not None and type(timestamp) is not int:
        raise TypeError("timestamp must be an integer Unix timestamp")
    ts = int(time.time()) if timestamp is None else timestamp
    if ts < 0:
        raise ValueError("timestamp must be non-negative")

    dev_bytes = device_id.encode("utf-8")
    hid_bytes = handshake_id.encode("utf-8")
    nonce_bytes = bytes(challenge_nonce)

    parts = [
        struct.pack(">I", len(DEVICE_AUTH_DOMAIN_SEPARATOR)),
        DEVICE_AUTH_DOMAIN_SEPARATOR,
        struct.pack(">I", len(dev_bytes)),
        dev_bytes,
        struct.pack(">I", len(hid_bytes)),
        hid_bytes,
        struct.pack(">I", len(nonce_bytes)),
        nonce_bytes,
        struct.pack(">Q", ts),
    ]
    return b"".join(parts)


@dataclass
class FreshnessChallenge:
    """Gateway-generated challenge tracking freshness and replay prevention."""

    nonce: bytes
    issued_at: float
    expires_at: float
    device_id: str
    consumed: bool = False

    @property
    def nonce_hex(self) -> str:
        return self.nonce.hex()

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = time.time() if current_time is None else current_time
        return now > self.expires_at


class GatewayChallengeManager:
    """Manages freshness challenges on the gateway to enforce single-use and expiry."""

    def __init__(self, ttl_seconds: float = DEFAULT_CHALLENGE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        # Maps nonce_hex -> FreshnessChallenge
        self._challenges: dict[str, FreshnessChallenge] = {}

    def issue_challenge(self, device_id: str) -> FreshnessChallenge:
        """Issue a fresh, cryptographically random challenge for a specific device."""
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string")

        import secrets
        nonce = secrets.token_bytes(CHALLENGE_NONCE_LENGTH)
        now = time.time()
        challenge = FreshnessChallenge(
            nonce=nonce,
            issued_at=now,
            expires_at=now + self._ttl,
            device_id=device_id.strip(),
            consumed=False,
        )
        self._challenges[challenge.nonce_hex] = challenge
        self._prune_expired(now)
        return challenge

    def validate_and_consume(
        self,
        device_id: str,
        challenge_nonce: bytes,
        current_time: Optional[float] = None,
    ) -> DeviceAuthStatus:
        """Validate challenge freshness, device binding, and consume it to prevent replay."""
        now = time.time() if current_time is None else current_time
        nonce_hex = challenge_nonce.hex() if isinstance(challenge_nonce, (bytes, bytearray)) else ""

        challenge = self._challenges.get(nonce_hex)
        if challenge is None:
            # Replayed challenge that was already consumed or unknown challenge
            return DeviceAuthStatus.AUTH_CHALLENGE_REPLAYED

        if challenge.consumed:
            return DeviceAuthStatus.AUTH_CHALLENGE_REPLAYED

        if challenge.device_id != device_id:
            return DeviceAuthStatus.AUTH_MALFORMED

        if challenge.is_expired(now):
            return DeviceAuthStatus.AUTH_CHALLENGE_EXPIRED

        # Mark single-use consumption
        challenge.consumed = True
        return DeviceAuthStatus.AUTH_SUCCESS

    def _prune_expired(self, now: float) -> None:
        """Remove expired challenges to bound memory footprint."""
        # Retain consumed or expired records briefly or prune old ones
        expired_keys = [
            k for k, v in self._challenges.items() if (v.expires_at + 300.0) < now
        ]
        for k in expired_keys:
            self._challenges.pop(k, None)


def verify_device_signature(
    *,
    device_id: str,
    handshake_id: str,
    challenge_nonce: bytes,
    timestamp: int,
    signature: bytes,
    enrolled_public_key_bytes: bytes,
) -> bool:
    """Verify Ed25519 signature over canonical authentication message."""
    try:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            return False
        if not isinstance(enrolled_public_key_bytes, (bytes, bytearray)) or len(enrolled_public_key_bytes) != 32:
            return False

        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(enrolled_public_key_bytes))
        canonical_msg = build_canonical_device_auth_message(
            device_id=device_id,
            handshake_id=handshake_id,
            challenge_nonce=challenge_nonce,
            timestamp=timestamp,
        )
        pub_key.verify(bytes(signature), canonical_msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
