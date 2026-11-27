"""
QERIS Step 4: Local In-Process Device Simulator.

This module provides a local, in-process simulation of a device-to-gateway
cryptographic flow for Demo 1.

It exercises and connects existing cryptographic components:
- PQC profile: ML-KEM-512 + context-bound HKDF-SHA256 + AES-256-GCM.
- Classical profile: X25519 + context-bound HKDF-SHA256 + AES-256-GCM.
- Hybrid profile: X25519MLKEM768 (X25519 + ML-KEM-768) using the
  concatenated PQ/T key-agreement approach described in RFC 9958, with the
  component-share ordering of the RFC 10024 TLS group, followed by QERIS's
  context-bound HKDF-SHA256 + AES-256-GCM.

Hybrid is an in-process simulator profile, not a TLS 1.3 or DTLS 1.3
implementation. It must not be described as interoperable with those protocols.

Architectural and Security Boundaries:
1. LOCAL SIMULATION ONLY:
   This module does not implement or modify network transports, sockets, or real
   gateway handlers.
2. NO AUTHORIZATION DECISION:
   This module does not make an ALLOW authorization decision. Authorization is
   reported as NOT_PERFORMED.
3. DEVICE AUTHENTICATION IS UNRESOLVED:
   Device authentication is explicitly reported as SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED.
   Matching shared secrets or key fingerprints prove cryptographic agreement, but do
   NOT prove device identity or authenticity.
4. RECEIVER-RESOLVED SENSITIVITY TIER:
   The simulated receiver resolves the flow's sensitivity tier. Devices must not
   supply or assert their own sensitivity tier.
5. CONFIDENTIALITY:
   Private keys, shared secrets, session keys, and plaintext payloads are never logged
   or exposed in diagnostic outputs. Only non-secret cryptographic fingerprints and
   metadata are reported.
6. RECOVERY POLICY BELONGS TO S3:
   The optional on_failure callback in SimulatorConfig is an informational hook only.
   This module raises failures; it never makes or suppresses a recovery decision.
7. HARDWARE NOT VALIDATED:
   Compute delays are synthetic and are not calibrated from real ESP32 measurements.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import time
from typing import Any, Final, Optional

from qeris.secure_message import MessageContext, MessageDecryptor, MessageEncryptor
from qeris.device_auth import Ed25519DeviceCredential
from qeris.session_crypto import (
    compute_handshake_id,
    decapsulate,
    derive_session_key,
    encapsulate,
    generate_keypair,
    shared_secret_fingerprint,
)
from qeris.hybrid_session_crypto import (
    HYBRID_GROUP,
    CLIENT_KEY_SHARE_LENGTH,
    SERVER_KEY_SHARE_LENGTH,
    HybridKeyPair,
    compute_hybrid_handshake_id,
    decapsulate_hybrid,
    derive_hybrid_session_key,
    encapsulate_hybrid,
    generate_hybrid_keypair,
    hybrid_shared_secret_fingerprint,
)

# Demo 1 TEST ONLY defaults
TEST_ONLY_DEFAULT_POLICY_VERSION: Final[int] = 1
TEST_ONLY_DEFAULT_FLOW_MAPPING: Final[dict[str, str]] = {
    "FLOW-TEMP-01": "LOW",
    "FLOW-PRESSURE-02": "LOW",
    "FLOW-DEFAULT": "LOW",
}


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

class DeviceProfile(str, Enum):
    """Supported simulator device profiles.

    PQC       — ML-KEM-512 + QERIS HKDF-SHA256 + AES-256-GCM.
    CLASSICAL — X25519 + QERIS HKDF-SHA256 + AES-256-GCM.
    HYBRID    — X25519 + ML-KEM-768 using the RFC 9958-described concatenated
                PQ/T hybrid key-agreement approach; QERIS HKDF-SHA256 + AES-256-GCM.

    HYBRID uses the component-share/secret ordering of RFC 10024's
    X25519MLKEM768 TLS group. This is an in-process simulator profile, not a
    TLS 1.3 / DTLS 1.3 implementation.
    """

    PQC = "PQC"
    CLASSICAL = "CLASSICAL"
    HYBRID = "HYBRID"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SimulatorError(Exception):
    """Base exception for device simulator errors."""


class UnknownFlowError(SimulatorError, ValueError):
    """Raised when a flow identifier cannot be resolved to a sensitivity tier."""


class InvalidPayloadError(SimulatorError, TypeError, ValueError):
    """Raised when a telemetry payload is invalid or malformed."""


class InvalidProfileError(SimulatorError, ValueError):
    """Raised when an unsupported or unknown device profile is requested."""


class SimulatorTimeoutError(SimulatorError):
    """Raised when a simulated operation exceeds the configured timeout.

    Recovery decisions are the responsibility of S3; this module only signals
    that the timeout threshold was exceeded.
    """


# ---------------------------------------------------------------------------
# Structured Device Event Logging (S1/S4 Contract)
# ---------------------------------------------------------------------------

STRUCTURED_DEVICE_EVENT_FIELDS: Final[tuple[str, ...]] = (
    "ts",
    "device_id",
    "flow_id",
    "event",
    "mode",
    "cause",
    "size_bytes",
    "duration_ms",
)


def create_device_event(
    *,
    device_id: str,
    flow_id: str,
    event: str,
    mode: str,
    cause: str = "none",
    size_bytes: int = 0,
    duration_ms: float = 0.0,
    ts: int | None = None,
) -> dict[str, Any]:
    """Create a structured device event dictionary strictly adhering to the 8 agreed fields:
    ts, device_id, flow_id, event, mode, cause, size_bytes, duration_ms.

    Confidentiality guarantee:
        Never contains or exposes private keys, shared secrets, session keys,
        or sensitive plaintext payloads.
    """
    if ts is None:
        ts = int(time.time() * 1000)
    return {
        "ts": int(ts),
        "device_id": str(device_id),
        "flow_id": str(flow_id),
        "event": str(event),
        "mode": str(mode),
        "cause": str(cause),
        "size_bytes": int(size_bytes),
        "duration_ms": round(float(duration_ms), 3),
    }


def serialize_device_event(event_dict: Mapping[str, Any]) -> str:
    """Serialize a structured device event to a canonical JSON string."""
    return json.dumps(dict(event_dict), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Simulator configuration
# ---------------------------------------------------------------------------

@dataclass
class SimulatorConfig:
    """Optional configuration for synthetic delay, timeout, and failure notification.

    Attributes:
        profile:
            The device profile to use. Defaults to DeviceProfile.PQC.
        compute_delay_seconds:
            Synthetic delay injected before each major crypto operation
            (keypair generation and handshake completion) to emulate constrained
            device compute time.  Must be non-negative.  Defaults to 0 (no delay).
            NOTE: This is a synthetic test-only delay; it is NOT calibrated from
            real ESP32 measurements.
        timeout_seconds:
            If > 0, raise SimulatorTimeoutError when compute_delay_seconds exceeds
            this threshold.  Useful for testing timeout-detection paths without
            actually sleeping for long durations.  Defaults to 0 (disabled).
        on_failure:
            Optional callable invoked with (phase: str, exc: Exception) immediately
            before this module re-raises an exception.  S1 exposes this hook for
            observability; recovery policy decisions belong to S3.  The callable
            must not suppress exceptions.
        event_hook:
            Optional callable invoked with a structured device event dictionary
            conforming to the 8 canonical fields (ts, device_id, flow_id, event,
            mode, cause, size_bytes, duration_ms) on each relevant device event.
    """

    profile: DeviceProfile = DeviceProfile.PQC
    compute_delay_seconds: float = 0.0
    timeout_seconds: float = 0.0
    on_failure: Optional[Callable[[str, Exception], None]] = field(
        default=None, compare=False, repr=False
    )
    event_hook: Optional[Callable[[dict[str, Any]], None]] = field(
        default=None, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.profile, DeviceProfile):
            raise InvalidProfileError(
                f"profile must be a DeviceProfile enum member, got {self.profile!r}. "
                "Hint: use DeviceProfile.PQC, DeviceProfile.CLASSICAL, "
                "or DeviceProfile.HYBRID."
            )
        if not isinstance(self.compute_delay_seconds, (int, float)) or self.compute_delay_seconds < 0:
            raise ValueError("compute_delay_seconds must be a non-negative number")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds < 0:
            raise ValueError("timeout_seconds must be a non-negative number")
        if self.on_failure is not None and not callable(self.on_failure):
            raise TypeError("on_failure must be callable or None")
        if self.event_hook is not None and not callable(self.event_hook):
            raise TypeError("event_hook must be callable or None")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_key_fingerprint(key: bytes) -> str:
    """Return a non-secret SHA-256 hex fingerprint of a key for diagnostic comparison only."""
    return hashlib.sha256(key).hexdigest()


def _apply_delay(config: SimulatorConfig, phase: str) -> None:
    """Apply synthetic compute delay; raise SimulatorTimeoutError if threshold exceeded.

    The delay is purely synthetic and is not calibrated from real hardware.
    Timeout detection is signalled to the caller; recovery is S3's responsibility.
    """
    delay = config.compute_delay_seconds
    if delay <= 0:
        return
    timeout = config.timeout_seconds
    if timeout > 0 and delay > timeout:
        exc = SimulatorTimeoutError(
            f"Simulated compute delay {delay:.3f}s exceeds timeout {timeout:.3f}s "
            f"during phase '{phase}'. Recovery decisions belong to S3."
        )
        if config.on_failure is not None:
            try:
                config.on_failure(phase, exc)
            except Exception:  # noqa: BLE001
                pass  # on_failure must not suppress the original exception
        raise exc
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Classical profile helpers (X25519)
# ---------------------------------------------------------------------------

def _classical_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 ephemeral keypair; return (public_key_bytes, private_key_bytes)."""
    from qeris_classical.session_crypto import generate_keypair as _cls_gen
    return _cls_gen()


def _classical_derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Perform X25519 ECDH and return the 32-byte shared secret."""
    from qeris_classical.session_crypto import derive_shared_secret as _cls_dh
    return _cls_dh(private_key, peer_public_key)


def _classical_derive_session_key(
    shared_secret: bytes,
    *,
    device_id: str,
    flow_id: str,
    sensitivity_tier: str,
    policy_version: int,
) -> bytes:
    """Derive a context-bound 256-bit session key from the X25519 shared secret."""
    from qeris_classical.session_crypto import derive_session_key as _cls_kdf
    return _cls_kdf(
        shared_secret,
        device_id=device_id,
        flow_id=flow_id,
        sensitivity_tier=sensitivity_tier,
        policy_version=policy_version,
    )


def _classical_shared_secret_fingerprint(shared_secret: bytes) -> str:
    """Return a non-secret SHA-256 fingerprint of the shared secret."""
    from qeris_classical.session_crypto import shared_secret_fingerprint as _cls_fp
    return _cls_fp(shared_secret)


# ---------------------------------------------------------------------------
# SimulationResult
# ---------------------------------------------------------------------------

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
    handshake_id: str = ""
    profile: str = DeviceProfile.PQC.value
    authorization_decision: str = "NOT_PERFORMED"
    authorization_note: str = (
        "Authorization has not been performed; local crypto simulation only. "
        "No ALLOW decision is made by this module."
    )
    device_authentication_status: str = "SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED"
    device_authentication_note: str = (
        "The simulator can sign a challenge-bound handshake using its Ed25519 credential; "
        "gateway registry verification is outside this local round-trip."
    )
    success: bool = True
    events: tuple[dict[str, Any], ...] = ()


# ---------------------------------------------------------------------------
# SimulatedReceiver
# ---------------------------------------------------------------------------

class SimulatedReceiver:
    """Simulates the gateway/receiver side of the cryptographic handshake and telemetry ingestion.

    Resolves flow sensitivity tiers independently and maintains session state.
    Profile-specific key exchange is handled transparently.
    """

    def __init__(
        self,
        flow_tier_map: Mapping[str, str] | None = None,
        policy_version: int = TEST_ONLY_DEFAULT_POLICY_VERSION,
        profile: DeviceProfile = DeviceProfile.PQC,
    ) -> None:
        if not isinstance(profile, DeviceProfile):
            raise InvalidProfileError(
                f"profile must be a DeviceProfile enum member, got {profile!r}"
            )
        if flow_tier_map is None:
            self._flow_tier_map: dict[str, str] = dict(TEST_ONLY_DEFAULT_FLOW_MAPPING)
        else:
            self._flow_tier_map = dict(flow_tier_map)
        self._policy_version = policy_version
        self._profile = profile
        self._session_key: bytes | None = None
        self._shared_secret_fp: str | None = None
        self._session_key_fp: str | None = None
        self._decryptor: MessageDecryptor | None = None
        self._active_context: MessageContext | None = None
        self._handshake_id: str | None = None
        # Classical-only: receiver ephemeral keypair for X25519.
        self._classical_private_key: bytes | None = None
        self._classical_public_key: bytes | None = None

    @property
    def shared_secret_fingerprint(self) -> str | None:
        return self._shared_secret_fp

    @property
    def session_key_fingerprint(self) -> str | None:
        return self._session_key_fp

    @property
    def handshake_id(self) -> str | None:
        return self._handshake_id

    @property
    def profile(self) -> DeviceProfile:
        return self._profile

    # --- Classical: expose receiver public key so device can complete ECDH ---

    def generate_classical_ephemeral(self) -> bytes:
        """Generate a fresh X25519 ephemeral keypair for the receiver.

        Returns the raw 32-byte public key for transmission to the device.
        Only valid when profile=CLASSICAL.
        """
        if self._profile is not DeviceProfile.CLASSICAL:
            raise InvalidProfileError(
                "generate_classical_ephemeral() is only valid for CLASSICAL profile"
            )
        pub, priv = _classical_generate_keypair()
        self._classical_public_key = pub
        self._classical_private_key = priv
        return pub

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
        """Process device handshake: resolve tier, perform key exchange, derive session key.

        For PQC:       device_public_key is an ML-KEM-512 public key.
        For CLASSICAL: device_public_key is an X25519 public key; call
                       generate_classical_ephemeral() before this method.
        For HYBRID:    device_public_key is the RFC 10024-shaped client share:
                       ML-KEM-768 public key || X25519 public key. Returns the
                       server share: ML-KEM-768 ciphertext || X25519 public key.

        Returns (server_share_or_ciphertext, sensitivity_tier, policy_version).
        """
        if not isinstance(device_id, str) or not device_id.strip():
            raise SimulatorError("device_id must be a non-empty string")

        sensitivity_tier = self.resolve_flow_tier(flow_id)

        if self._profile is DeviceProfile.PQC:
            ciphertext, shared_secret = encapsulate(device_public_key)
            self._shared_secret_fp = shared_secret_fingerprint(shared_secret)
            self._session_key = derive_session_key(
                shared_secret,
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=self._policy_version,
            )
            # Compute handshake_id using the PQC transcript hash
            self._handshake_id = compute_handshake_id(
                device_public_key,
                ciphertext,
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=self._policy_version,
            )
            handshake_token = ciphertext

        elif self._profile is DeviceProfile.CLASSICAL:
            if self._classical_private_key is None or self._classical_public_key is None:
                raise SimulatorError(
                    "Call generate_classical_ephemeral() before handle_handshake() "
                    "for CLASSICAL profile"
                )
            shared_secret = _classical_derive_shared_secret(
                self._classical_private_key, device_public_key
            )
            self._shared_secret_fp = _classical_shared_secret_fingerprint(shared_secret)
            self._session_key = _classical_derive_session_key(
                shared_secret,
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=self._policy_version,
            )
            # For CLASSICAL, handshake_id is a SHA-256 hash of a canonical encoding
            # of both ephemeral public keys and the context, providing a correlation
            # token (not a KEM transcript).
            import hashlib, struct as _struct
            dev_pk_b = bytes(device_public_key) if isinstance(device_public_key, (bytes, bytearray)) else b""
            rec_pk_b = self._classical_public_key
            ctx = (
                device_id.encode("utf-8") + b"\x00"
                + flow_id.encode("utf-8") + b"\x00"
                + sensitivity_tier.encode("utf-8") + b"\x00"
                + _struct.pack(">Q", self._policy_version)
            )
            transcript = (
                b"QERIS-CLASSICAL-TRANSCRIPT-v1\x00"
                + _struct.pack(">I", len(dev_pk_b)) + dev_pk_b
                + _struct.pack(">I", len(rec_pk_b)) + rec_pk_b
                + _struct.pack(">I", len(ctx)) + ctx
            )
            self._handshake_id = hashlib.sha256(transcript).hexdigest()
            handshake_token = self._classical_public_key  # receiver's pub key is the "ciphertext"

        elif self._profile is DeviceProfile.HYBRID:
            if len(device_public_key) != CLIENT_KEY_SHARE_LENGTH:
                raise SimulatorError(
                    f"HYBRID client key share must be {CLIENT_KEY_SHARE_LENGTH} bytes"
                )
            encapsulation = encapsulate_hybrid(device_public_key)
            combined_shared_secret = encapsulation.combined_shared_secret
            self._shared_secret_fp = hybrid_shared_secret_fingerprint(
                combined_shared_secret
            )
            handshake_token = encapsulation.server_key_share
            self._handshake_id = compute_hybrid_handshake_id(
                device_public_key,
                handshake_token,
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=self._policy_version,
            )
            self._session_key = derive_hybrid_session_key(
                combined_shared_secret,
                device_id=device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=self._policy_version,
                handshake_id=self._handshake_id,
            )

        else:  # pragma: no cover
            raise InvalidProfileError(f"Unsupported profile: {self._profile}")

        self._session_key_fp = compute_key_fingerprint(self._session_key)

        # Initialize decryptor using the AES-256-GCM API (shared by both profiles)
        self._active_context = MessageContext(
            device_id=device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=self._policy_version,
        )
        self._decryptor = MessageDecryptor(self._session_key, self._active_context)

        return handshake_token, sensitivity_tier, self._policy_version

    def receive_telemetry(self, envelope: bytes) -> bytes:
        """Decrypt AEAD protected message using existing secure_message API."""
        if self._decryptor is None:
            raise SimulatorError("Receiver has not established a session")
        return self._decryptor.decrypt(envelope)


# ---------------------------------------------------------------------------
# SimulatedDevice
# ---------------------------------------------------------------------------

class SimulatedDevice:
    """Simulates an IoT edge device creating a keypair, completing the handshake,

    and encrypting telemetry messages.

    Supports PQC (ML-KEM-512), CLASSICAL (X25519), and HYBRID
    (X25519MLKEM768) in the local in-process simulator.
    """

    def __init__(
        self,
        device_id: str,
        device_credential: Ed25519DeviceCredential | None = None,
        config: SimulatorConfig | None = None,
    ) -> None:
        if not isinstance(device_id, str) or not device_id.strip():
            raise SimulatorError("device_id must be a non-empty string")
        self._device_id = device_id
        self._device_credential = device_credential or Ed25519DeviceCredential()
        self._config: SimulatorConfig = config if config is not None else SimulatorConfig()
        self._profile: DeviceProfile = self._config.profile

        self._public_key: bytes | None = None
        self._secret_key: bytes | None = None
        self._hybrid_keypair: HybridKeyPair | None = None
        self._session_key: bytes | None = None
        self._shared_secret_fp: str | None = None
        self._session_key_fp: str | None = None
        self._encryptor: MessageEncryptor | None = None
        self._active_context: MessageContext | None = None
        self._handshake_id: str | None = None
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        """Return immutable tuple of structured device events emitted by this device."""
        return tuple(self._events)

    def _record_event(
        self,
        event_name: str,
        *,
        flow_id: str = "FLOW-DEFAULT",
        cause: str = "none",
        size_bytes: int = 0,
        duration_ms: float = 0.0,
    ) -> dict[str, Any]:
        resolved_flow = flow_id or (self._active_context.flow_id if self._active_context else "FLOW-DEFAULT")
        ev = create_device_event(
            device_id=self._device_id,
            flow_id=resolved_flow,
            event=event_name,
            mode=self._profile.value,
            cause=cause,
            size_bytes=size_bytes,
            duration_ms=duration_ms,
        )
        self._events.append(ev)
        if self._config.event_hook is not None:
            try:
                self._config.event_hook(ev)
            except Exception:  # noqa: BLE001
                pass
        return ev

    @property
    def shared_secret_fingerprint(self) -> str | None:
        return self._shared_secret_fp

    @property
    def session_key_fingerprint(self) -> str | None:
        return self._session_key_fp

    @property
    def handshake_id(self) -> str | None:
        return self._handshake_id

    @property
    def profile(self) -> DeviceProfile:
        return self._profile

    @property
    def device_auth_public_key(self) -> bytes:
        """Return the long-term Ed25519 public key for out-of-band enrollment."""
        return self._device_credential.public_key_bytes

    def sign_handshake_authentication(self, challenge_nonce: bytes, timestamp: int | None = None) -> bytes:
        """Sign the completed handshake using the device's long-term Ed25519 credential."""
        if self._handshake_id is None:
            raise SimulatorError("Device has not completed the KEM handshake")
        return self._device_credential.sign_authentication_message(
            device_id=self._device_id,
            handshake_id=self._handshake_id,
            challenge_nonce=challenge_nonce,
            timestamp=timestamp,
        )

    def generate_kem_keypair(self, flow_id: str = "FLOW-DEFAULT") -> bytes:
        """Create a fresh device keypair according to the configured profile.

        PQC:       Generate ML-KEM-512 keypair; return 800-byte public key.
        CLASSICAL: Generate X25519 ephemeral keypair; return 32-byte public key.
        HYBRID:    Generate ML-KEM-768 and X25519 keypairs; return the 1216-byte
                   client share (ML-KEM public key || X25519 public key).

        A synthetic compute delay is applied if configured (not calibrated from hardware).
        Raises SimulatorTimeoutError if the delay exceeds the configured timeout.
        """
        t0 = time.perf_counter()
        _apply_delay(self._config, "keypair_generation")
        if self._profile is DeviceProfile.PQC:
            self._public_key, self._secret_key = generate_keypair()
        elif self._profile is DeviceProfile.CLASSICAL:
            self._public_key, self._secret_key = _classical_generate_keypair()
        elif self._profile is DeviceProfile.HYBRID:
            self._hybrid_keypair = generate_hybrid_keypair()
            self._public_key = self._hybrid_keypair.client_key_share
            self._secret_key = None
        else:  # pragma: no cover
            raise InvalidProfileError(f"Unsupported profile: {self._profile}")
        dur = (time.perf_counter() - t0) * 1000.0
        self._record_event(
            "connection_start",
            flow_id=flow_id,
            size_bytes=len(self._public_key) if self._public_key else 0,
            duration_ms=dur,
        )
        return self._public_key

    def complete_handshake(
        self,
        ciphertext: bytes,
        flow_id: str,
        sensitivity_tier: str,
        policy_version: int,
        *,
        receiver_handshake_id: str | None = None,
    ) -> None:
        """Complete the device-side handshake and derive a session key.

        PQC:       ciphertext is the ML-KEM-512 KEM ciphertext.
        CLASSICAL: ciphertext is the receiver's X25519 ephemeral public key.
        HYBRID:    ciphertext is the 1120-byte server share:
                   ML-KEM-768 ciphertext || X25519 public key.

        HYBRID recomputes its transcript hash from both complete shares. If the
        receiver_handshake_id is supplied, it must match the locally computed hash.

        A synthetic compute delay is applied if configured (not calibrated from hardware).
        Raises SimulatorTimeoutError if the delay exceeds the configured timeout.
        """
        t0 = time.perf_counter()
        if self._profile is DeviceProfile.HYBRID:
            if self._hybrid_keypair is None:
                raise SimulatorError("Device has not generated its HYBRID keypair")
        elif self._secret_key is None:
            raise SimulatorError("Device has not generated a keypair")

        _apply_delay(self._config, "handshake_completion")

        if self._profile is DeviceProfile.PQC:
            shared_secret = decapsulate(ciphertext, self._secret_key)
            self._shared_secret_fp = shared_secret_fingerprint(shared_secret)
            self._session_key = derive_session_key(
                shared_secret,
                device_id=self._device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=policy_version,
            )
            if self._public_key is not None:
                self._handshake_id = compute_handshake_id(
                    self._public_key,
                    ciphertext,
                    device_id=self._device_id,
                    flow_id=flow_id,
                    sensitivity_tier=sensitivity_tier,
                    policy_version=policy_version,
                )

        elif self._profile is DeviceProfile.CLASSICAL:
            # ciphertext is the receiver's ephemeral X25519 public key
            receiver_pub_key = ciphertext
            shared_secret = _classical_derive_shared_secret(self._secret_key, receiver_pub_key)
            self._shared_secret_fp = _classical_shared_secret_fingerprint(shared_secret)
            self._session_key = _classical_derive_session_key(
                shared_secret,
                device_id=self._device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=policy_version,
            )
            # Accept the handshake_id computed authoritatively by the receiver
            if receiver_handshake_id is not None:
                self._handshake_id = receiver_handshake_id

        elif self._profile is DeviceProfile.HYBRID:
            if self._hybrid_keypair is None or self._public_key is None:
                raise SimulatorError("HYBRID device keypair state is unavailable")
            combined_shared_secret = decapsulate_hybrid(
                ciphertext, self._hybrid_keypair
            )
            self._shared_secret_fp = hybrid_shared_secret_fingerprint(
                combined_shared_secret
            )
            self._handshake_id = compute_hybrid_handshake_id(
                self._public_key,
                ciphertext,
                device_id=self._device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=policy_version,
            )
            if (
                receiver_handshake_id is not None
                and self._handshake_id != receiver_handshake_id
            ):
                raise SimulatorError(
                    "HYBRID handshake transcript does not match receiver transcript"
                )
            self._session_key = derive_hybrid_session_key(
                combined_shared_secret,
                device_id=self._device_id,
                flow_id=flow_id,
                sensitivity_tier=sensitivity_tier,
                policy_version=policy_version,
                handshake_id=self._handshake_id,
            )

        else:  # pragma: no cover
            raise InvalidProfileError(f"Unsupported profile: {self._profile}")

        self._session_key_fp = compute_key_fingerprint(self._session_key)

        # Initialize encryptor (AES-256-GCM, shared by both profiles)
        self._active_context = MessageContext(
            device_id=self._device_id,
            flow_id=flow_id,
            sensitivity_tier=sensitivity_tier,
            policy_version=policy_version,
        )
        self._encryptor = MessageEncryptor(self._session_key, self._active_context)
        dur = (time.perf_counter() - t0) * 1000.0
        pk_len = len(self._public_key) if self._public_key is not None else 0
        ct_len = len(ciphertext) if ciphertext is not None else 0
        self._record_event(
            "handshake_complete",
            flow_id=flow_id,
            size_bytes=pk_len + ct_len,
            duration_ms=dur,
        )

    def send_telemetry(self, payload: bytes) -> bytes:
        """Encrypt telemetry payload using existing secure_message API."""
        t0 = time.perf_counter()
        if self._encryptor is None:
            raise SimulatorError("Device has not completed handshake")
        if not isinstance(payload, bytes):
            raise InvalidPayloadError(f"Payload must be bytes, got {type(payload).__name__}")
        if len(payload) == 0:
            raise InvalidPayloadError("Payload must not be empty")
        envelope = self._encryptor.encrypt(payload)
        dur = (time.perf_counter() - t0) * 1000.0
        flow = self._active_context.flow_id if self._active_context else "FLOW-DEFAULT"
        self._record_event(
            "data_sent",
            flow_id=flow,
            size_bytes=len(envelope),
            duration_ms=dur,
        )
        return envelope


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def simulate_device_round_trip(
    device_id: str = "DEV-TEST-001",
    flow_id: str = "FLOW-TEMP-01",
    payload: bytes = b'{"temp_c": 23.4, "status": "nominal"}',
    flow_tier_map: Mapping[str, str] | None = None,
    policy_version: int = TEST_ONLY_DEFAULT_POLICY_VERSION,
    profile: DeviceProfile = DeviceProfile.PQC,
    config: SimulatorConfig | None = None,
) -> SimulationResult:
    """Run an end-to-end local in-process simulation of device-to-gateway telemetry.

    Args:
        device_id:      Logical device identifier.
        flow_id:        Flow identifier resolved to a sensitivity tier by the receiver.
        payload:        Telemetry payload bytes; must be non-empty.
        flow_tier_map:  Optional override for the receiver's flow-to-tier mapping.
        policy_version: Policy version bound into HKDF context.
        profile:        DeviceProfile.PQC (default), DeviceProfile.CLASSICAL,
                        or DeviceProfile.HYBRID (in-process X25519MLKEM768).
        config:         Optional SimulatorConfig for delay/timeout/on_failure.
                        If provided, its profile field takes precedence over the
                        ``profile`` argument.

    Returns:
        SimulationResult with diagnostic fields.  Never contains secret material.
    """
    start_time = time.perf_counter()

    # Resolve effective profile: config takes precedence if supplied
    if config is not None:
        effective_config = config
        effective_profile = config.profile
    else:
        effective_profile = profile
        effective_config = SimulatorConfig(profile=effective_profile)

    receiver = SimulatedReceiver(
        flow_tier_map=flow_tier_map,
        policy_version=policy_version,
        profile=effective_profile,
    )
    device = SimulatedDevice(device_id=device_id, config=effective_config)

    if not isinstance(payload, bytes):
        device._record_event(
            "failure",
            flow_id=flow_id,
            cause="invalid_payload",
            size_bytes=0,
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        )
        raise InvalidPayloadError(f"Payload must be bytes, got {type(payload).__name__}")
    if len(payload) == 0:
        device._record_event(
            "failure",
            flow_id=flow_id,
            cause="invalid_payload",
            size_bytes=0,
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        )
        raise InvalidPayloadError("Payload must not be empty")

    try:
        if effective_profile is DeviceProfile.PQC:
            # --- PQC path (ML-KEM-512) ---
            device_pk = device.generate_kem_keypair(flow_id=flow_id)
            ciphertext, resolved_tier, p_version = receiver.handle_handshake(
                device_id=device_id,
                flow_id=flow_id,
                device_public_key=device_pk,
            )
            device.complete_handshake(
                ciphertext=ciphertext,
                flow_id=flow_id,
                sensitivity_tier=resolved_tier,
                policy_version=p_version,
            )

        elif effective_profile is DeviceProfile.CLASSICAL:
            # --- Classical path (X25519) ---
            # Receiver generates its ephemeral keypair first
            receiver_pub = receiver.generate_classical_ephemeral()
            # Device generates its ephemeral keypair
            device_pk = device.generate_kem_keypair(flow_id=flow_id)
            # Receiver performs ECDH with device's public key; also computes handshake_id
            handshake_token, resolved_tier, p_version = receiver.handle_handshake(
                device_id=device_id,
                flow_id=flow_id,
                device_public_key=device_pk,
            )
            # Device performs ECDH with receiver's public key; handshake_id from receiver
            device.complete_handshake(
                ciphertext=receiver_pub,          # receiver pub key passed as "ciphertext"
                flow_id=flow_id,
                sensitivity_tier=resolved_tier,
                policy_version=p_version,
                receiver_handshake_id=receiver.handshake_id,
            )
            ciphertext = handshake_token          # receiver pub key; for result metadata

        elif effective_profile is DeviceProfile.HYBRID:
            # --- Hybrid path: RFC 10024 X25519MLKEM768 component-share order ---
            # Device share: ML-KEM-768 public key || X25519 public key.
            device_pk = device.generate_kem_keypair(flow_id=flow_id)
            server_share, resolved_tier, p_version = receiver.handle_handshake(
                device_id=device_id,
                flow_id=flow_id,
                device_public_key=device_pk,
            )
            device.complete_handshake(
                ciphertext=server_share,
                flow_id=flow_id,
                sensitivity_tier=resolved_tier,
                policy_version=p_version,
                receiver_handshake_id=receiver.handshake_id,
            )
            ciphertext = server_share

        else:  # pragma: no cover
            raise InvalidProfileError(f"Unsupported profile: {effective_profile}")

        handshake_ids_match = (
            device.handshake_id == receiver.handshake_id
            and device.handshake_id is not None
        )
        fingerprints_match = (
            device.shared_secret_fingerprint == receiver.shared_secret_fingerprint
            and device.session_key_fingerprint == receiver.session_key_fingerprint
            and device.session_key_fingerprint is not None
        )

        envelope = device.send_telemetry(payload)
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
            handshake_id=receiver.handshake_id or "",
            profile=effective_profile.value,
            success=(fingerprints_match and payload_matches and handshake_ids_match),
            events=device.events,
        )
    except Exception as exc:
        cause = "timeout" if isinstance(exc, SimulatorTimeoutError) else (
            "invalid_payload" if isinstance(exc, InvalidPayloadError) else (
                "invalid_profile" if isinstance(exc, InvalidProfileError) else exc.__class__.__name__
            )
        )
        device._record_event(
            "failure",
            flow_id=flow_id,
            cause=cause,
            size_bytes=0,
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        )
        raise
