"""QERIS-compatible AES-256-GCM message envelopes with replay protection.

The QMSG v1 header and AAD encoding intentionally match the integrated S1
qeris.secure_message implementation, allowing the classical-derived session
key to use the same message-envelope format. One encryptor/decryptor pair is
for one sending direction and one fresh session key.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_MAGIC: Final[bytes] = b"QMSG"
_VERSION: Final[int] = 1
_HEADER: Final[struct.Struct] = struct.Struct(">4sB12s")
_NONCE_SIZE: Final[int] = 12
_KEY_SIZE: Final[int] = 32
_MAX_COUNTER: Final[int] = (1 << 96) - 1
_MAX_CONTEXT_FIELD: Final[int] = 65535
MAX_ENVELOPE_SIZE: Final[int] = 1_048_576


class MessageCryptoError(ValueError):
    """Base class for message framing and cryptographic errors."""


class AuthenticationError(MessageCryptoError):
    """Raised when AES-GCM authentication fails."""


class ReplayError(MessageCryptoError):
    """Raised when a repeated or out-of-order message counter is received."""


@dataclass(frozen=True)
class MessageContext:
    device_id: str
    flow_id: str
    sensitivity_tier: str
    policy_version: int

    def encode(self) -> bytes:
        fields = (
            _encode_text(self.device_id, "device_id"),
            _encode_text(self.flow_id, "flow_id"),
            _encode_text(self.sensitivity_tier, "sensitivity_tier"),
        )
        if isinstance(self.policy_version, bool) or not isinstance(self.policy_version, int):
            raise MessageCryptoError("policy_version must be an integer")
        if not 0 <= self.policy_version <= 0xFFFFFFFFFFFFFFFF:
            raise MessageCryptoError("policy_version is outside the supported range")
        out = bytearray(b"QERIS-AAD-v1\x00")
        for field in fields:
            out.extend(struct.pack(">I", len(field)))
            out.extend(field)
        out.extend(struct.pack(">Q", self.policy_version))
        return bytes(out)


def _encode_text(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise MessageCryptoError(f"{field_name} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise MessageCryptoError(f"{field_name} must be valid UTF-8") from exc
    if len(encoded) > _MAX_CONTEXT_FIELD:
        raise MessageCryptoError(f"{field_name} is too long")
    return encoded


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != _KEY_SIZE:
        raise MessageCryptoError("session key must be exactly 32 bytes for AES-256-GCM")
    return key


class MessageEncryptor:
    """Encrypt messages for one direction using a monotonic 96-bit nonce."""

    def __init__(self, session_key: bytes, context: MessageContext) -> None:
        self._aead = AESGCM(_validate_key(session_key))
        if not isinstance(context, MessageContext):
            raise MessageCryptoError("context must be a MessageContext")
        self._context_aad = context.encode()
        self._counter = 0

    @property
    def next_counter(self) -> int:
        return self._counter

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise MessageCryptoError("plaintext must be bytes")
        if self._counter > _MAX_COUNTER:
            raise MessageCryptoError("message counter exhausted; establish a fresh session")
        if len(plaintext) + _HEADER.size + 16 > MAX_ENVELOPE_SIZE:
            raise MessageCryptoError("plaintext exceeds the maximum supported envelope size")
        nonce = self._counter.to_bytes(_NONCE_SIZE, "big")
        header = _HEADER.pack(_MAGIC, _VERSION, nonce)
        ciphertext_and_tag = self._aead.encrypt(nonce, plaintext, header + self._context_aad)
        self._counter += 1
        return header + ciphertext_and_tag


class MessageDecryptor:
    """Authenticate and decrypt one direction; advance replay state on success only."""

    def __init__(self, session_key: bytes, context: MessageContext) -> None:
        self._aead = AESGCM(_validate_key(session_key))
        if not isinstance(context, MessageContext):
            raise MessageCryptoError("context must be a MessageContext")
        self._context_aad = context.encode()
        self._last_counter = -1

    @property
    def last_counter(self) -> int:
        return self._last_counter

    def decrypt(self, envelope: bytes) -> bytes:
        if not isinstance(envelope, bytes):
            raise MessageCryptoError("envelope must be bytes")
        if len(envelope) < _HEADER.size + 16:
            raise MessageCryptoError("envelope is truncated")
        if len(envelope) > MAX_ENVELOPE_SIZE:
            raise MessageCryptoError(
                f"envelope exceeds maximum supported size of {MAX_ENVELOPE_SIZE} bytes"
            )
        try:
            magic, version, nonce = _HEADER.unpack(envelope[:_HEADER.size])
        except struct.error as exc:
            raise MessageCryptoError("malformed message header") from exc
        if magic != _MAGIC:
            raise MessageCryptoError("invalid message magic")
        if version != _VERSION:
            raise MessageCryptoError("unsupported message version")
        counter = int.from_bytes(nonce, "big")
        if counter <= self._last_counter:
            raise ReplayError("replayed or out-of-order message counter")
        header = envelope[:_HEADER.size]
        try:
            plaintext = self._aead.decrypt(nonce, envelope[_HEADER.size:], header + self._context_aad)
        except InvalidTag as exc:
            raise AuthenticationError("message authentication failed") from exc
        except (TypeError, ValueError) as exc:
            raise MessageCryptoError("message decryption failed") from exc
        self._last_counter = counter
        return plaintext
