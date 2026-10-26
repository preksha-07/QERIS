"""
QERIS Step 4: Local In-Process Device Simulator.

This module provides a local, in-process simulation of a device-to-gateway
cryptographic flow for Demo 1.

It exercises and connects existing cryptographic components:
- ML-KEM-512 keypair generation, encapsulation, and decapsulation (qeris.session_crypto)
- Context-bound session-key derivation via HKDF-SHA256 (qeris.session_crypto)
- Authenticated telemetry encryption and decryption via AES-256-GCM (qeris.secure_message)

Architectural and Security Boundaries:
1. LOCAL SIMULATION ONLY:
   This module does not implement or modify network transports, sockets, or real gateway handlers.
2. NO AUTHORIZATION DECISION:
   This module does not make an ALLOW authorization decision. Authorization is reported
   as NOT_PERFORMED.
3. DEVICE AUTHENTICATION IS UNRESOLVED:
   Device authentication is explicitly reported as NOT_IMPLEMENTED. Matching KEM shared
   secrets or key fingerprints prove cryptographic agreement, but do NOT prove device
   identity or authenticity.
4. RECEIVER-RESOLVED SENSITIVITY TIER:
   The simulated receiver resolves the flow's sensitivity tier. Devices must not supply
   or assert their own sensitivity tier.
5. CONFIDENTIALITY:
   Private keys, shared secrets, session keys, and plaintext payloads are never logged
   or exposed in diagnostic outputs. Only non-secret cryptographic fingerprints and
   metadata are reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from typing import Final

from qeris.secure_message import MessageContext, MessageDecryptor, MessageEncryptor
from qeris.session_crypto import (
    decapsulate,
    derive_session_key,
    encapsulate,
    generate_keypair,
    shared_secret_fingerprint,
)

# Demo 1 TEST ONLY defaults
TEST_ONLY_DEFAULT_POLICY_VERSION: Final[int] = 1
TEST_ONLY_DEFAULT_FLOW_MAPPING: Final[dict[str, str]] = {
    "FLOW-TEMP-01": "LOW",
    "FLOW-PRESSURE-02": "LOW",
    "FLOW-DEFAULT": "LOW",
}


class SimulatorError(Exception):
    """Base exception for device simulator errors."""


class UnknownFlowError(SimulatorError, ValueError):
    """Raised when a flow identifier cannot be resolved to a sensitivity tier."""


class InvalidPayloadError(SimulatorError, TypeError, ValueError):
    """Raised when a telemetry payload is invalid or malformed."""


def compute_key_fingerprint(key: bytes) -> str:
    """Return a non-secret SHA-256 hex fingerprint of a key for diagnostic comparison only."""
    return hashlib.sha256(key).hexdigest()


@dataclass(frozen=True)
class SimulationResult:
    """Structured diagnostic summary of a simulated device-to-gateway round-trip.

    Confidentiality guarantee:
    Does NOT contain or expose private keys, shared secrets, session keys, or raw plaintext.
    """

    device_id: str
    flow_id: str
    sensitivity_tier: str
    policy_version: int
    public_key_length: int
    ciphertext_length: int
    shared_secret_fingerprint: str
    session_key_fingerprint: str
    fingerprints_match: bool
    envelope_length: int
    received_payload_matches: bool
    authorization_decision: str = "NOT_PERFORMED"
    authorization_note: str = (
        "Authorization has not been performed; local crypto simulation only. "
        "No ALLOW decision is made by this module."
    )
    device_authentication_status: str = "NOT_IMPLEMENTED"
    device_authentication_note: str = (
        "Device authentication is unresolved in Demo 1. "
        "Matching KEM secrets and fingerprints do NOT prove device identity or authenticity."
    )
    success: bool = True


class SimulatedReceiver:
    """Simulates the gateway/receiver side of the cryptographic handshake and telemetry ingestion.

    Resolves flow sensitivity tiers independently and maintains session state.
    """

    def __init__(
        self,
        flow_tier_map: Mapping[str, str] | None = None,
        policy_version: int = TEST_ONLY_DEFAULT_POLICY_VERSION,
    ) -> None:
        if flow_tier_map is None:
            self._flow_tier_map: dict[str, str] = dict(TEST_ONLY_DEFAULT_FLOW_MAPPING)
        else:
            self._flow_tier_map = dict(flow_tier_map)
        self._policy_version = policy_version
        self._session_key: bytes | None = None
        self._shared_secret_fp: str | None = None
        self._session_key_fp: str | None = None
        self._decryptor: MessageDecryptor | None = None
        self._active_context: MessageContext | None = None

    @property
    def shared_secret_fingerprint(self) -> str | None:
        return self._shared_secret_fp

    @property
    def session_key_fingerprint(self) -> str | None:
        return self._session_key_fp

    def resolve_flow_tier(self, flow_id: str) -> str:
        """Resolve flow sensitivity tier from local flow mapping table.

        The device must not provide its own sensitivity tier.
        """
        if not isinstance(flow_id, str) or not flow_id.strip():
            raise UnknownFlowError("flow_id must be a non-empty string")
        if flow_id not in self._flow_tier_map:
            raise UnknownFlowError(
                f"Unknown flow identifier '{flow_id}'; cannot resolve sensitivity tier"
            )
        return self._flow_tier_map[flow_id]

    def handle_handshake(
        self,
        device_id: str,
        flow_id: str,
        device_public_key: bytes,
    ) -> tuple[bytes, str, int]:
        """Process device handshake: resolve tier, encapsulate, derive receiver session key.

        Returns (ciphertext, sensitivity_tier, policy_version).
        """
        if not isinstance(device_id, str) or not device_id.strip():
            raise SimulatorError("device_id must be a non-empty string")

        sensitivity_tier = self.resolve_flow_tier(flow_id)

        # Encapsulate using existing session_crypto API
        ciphertext, shared_secret = encapsulate(device_public_key)
        self._shared_secret_fp = shared_secret_fingerprint(shared_secret)

        # Derive receiver session key using existing session_crypto API
        self._session_key = derive_session_key(
            shared_secret,
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=self._policy_version,
        )
        self._session_key_fp = compute_key_fingerprint(self._session_key)

        # Initialize decryptor using existing secure_message API
        self._active_context = MessageContext(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=self._policy_version,
        )
        self._decryptor = MessageDecryptor(self._session_key, self._active_context)

        return ciphertext, sensitivity_tier, self._policy_version

    def receive_telemetry(self, envelope: bytes) -> bytes:
        """Decrypt AEAD protected message using existing secure_message API."""
        if self._decryptor is None:
            raise SimulatorError("Receiver has not established a session")
        return self._decryptor.decrypt(envelope)


class SimulatedDevice:
    """Simulates an IoT edge device creating a keypair, completing KEM handshake,

    and encrypting telemetry messages.
    """

    def __init__(self, device_id: str) -> None:
        if not isinstance(device_id, str) or not device_id.strip():
            raise SimulatorError("device_id must be a non-empty string")
        self._device_id = device_id
        self._public_key: bytes | None = None
        self._secret_key: bytes | None = None
        self._session_key: bytes | None = None
        self._shared_secret_fp: str | None = None
        self._session_key_fp: str | None = None
        self._encryptor: MessageEncryptor | None = None
        self._active_context: MessageContext | None = None

    @property
    def shared_secret_fingerprint(self) -> str | None:
        return self._shared_secret_fp

    @property
    def session_key_fingerprint(self) -> str | None:
        return self._session_key_fp

    def generate_kem_keypair(self) -> bytes:
        """Create fresh ML-KEM-512 keypair. Returns public key for transmission."""
        self._public_key, self._secret_key = generate_keypair()
        return self._public_key

    def complete_handshake(
        self,
        ciphertext: bytes,
        flow_id: str,
        sensitivity_tier: str,
        policy_version: int,
    ) -> None:
        """Decapsulate ciphertext and derive device session key using receiver-assigned tier."""
        if self._secret_key is None:
            raise SimulatorError("Device has not generated a keypair")

        # Decapsulate using existing session_crypto API
        shared_secret = decapsulate(ciphertext, self._secret_key)
        self._shared_secret_fp = shared_secret_fingerprint(shared_secret)

        # Derive device session key using existing session_crypto API
        self._session_key = derive_session_key(
            shared_secret,
            device_id=self._device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=policy_version,
        )
        self._session_key_fp = compute_key_fingerprint(self._session_key)

        # Initialize encryptor using existing secure_message API
        self._active_context = MessageContext(
            device_id=self._device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=policy_version,
        )
        self._encryptor = MessageEncryptor(self._session_key, self._active_context)

    def send_telemetry(self, payload: bytes) -> bytes:
        """Encrypt telemetry payload using existing secure_message API."""
        if self._encryptor is None:
            raise SimulatorError("Device has not completed handshake")
        if not isinstance(payload, bytes):
            raise InvalidPayloadError(f"Payload must be bytes, got {type(payload).__name__}")
        if len(payload) == 0:
            raise InvalidPayloadError("Payload must not be empty")
        return self._encryptor.encrypt(payload)


def simulate_device_round_trip(
    device_id: str = "DEV-TEST-001",
    flow_id: str = "FLOW-TEMP-01",
    payload: bytes = b'{"temp_c": 23.4, "status": "nominal"}',
    flow_tier_map: Mapping[str, str] | None = None,
    policy_version: int = TEST_ONLY_DEFAULT_POLICY_VERSION,
) -> SimulationResult:
    """Run an end-to-end local in-process simulation of device-to-gateway telemetry."""
    if not isinstance(payload, bytes):
        raise InvalidPayloadError(f"Payload must be bytes, got {type(payload).__name__}")
    if len(payload) == 0:
        raise InvalidPayloadError("Payload must not be empty")

    receiver = SimulatedReceiver(flow_tier_map=flow_tier_map, policy_version=policy_version)
    device = SimulatedDevice(device_id=device_id)

    # 1. Device creates fresh ML-KEM-512 keypair
    device_pk = device.generate_kem_keypair()

    # 2. Receiver resolves tier and encapsulates to device public key
    ciphertext, resolved_tier, p_version = receiver.handle_handshake(
        device_id=device_id,
        flow_id=flow_id,
        device_public_key=device_pk,
    )

    # 3. Device decapsulates and derives session key with receiver-resolved tier
    device.complete_handshake(
        ciphertext=ciphertext,
        flow_id=flow_id,
        sensitivity_tier=resolved_tier,
        policy_version=p_version,
    )

    # 4. Compare fingerprints
    fingerprints_match = (
        device.shared_secret_fingerprint == receiver.shared_secret_fingerprint
        and device.session_key_fingerprint == receiver.session_key_fingerprint
        and device.session_key_fingerprint is not None
    )

    # 5. Create AEAD-protected telemetry message
    envelope = device.send_telemetry(payload)

    # 6. Decrypt at receiver and verify match
    received_plaintext = receiver.receive_telemetry(envelope)
    payload_matches = (received_plaintext == payload)

    return SimulationResult(
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=resolved_tier,
        policy_version=p_version,
        public_key_length=len(device_pk),
        ciphertext_length=len(ciphertext),
        shared_secret_fingerprint=device.shared_secret_fingerprint or "",
        session_key_fingerprint=device.session_key_fingerprint or "",
        fingerprints_match=fingerprints_match,
        envelope_length=len(envelope),
        received_payload_matches=payload_matches,
        success=(fingerprints_match and payload_matches),
    )
