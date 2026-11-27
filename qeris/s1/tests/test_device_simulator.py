"""Tests for QERIS Step 4: Local In-Process Device Simulator."""

import json
import unittest

from qeris.device_simulator import (
    STRUCTURED_DEVICE_EVENT_FIELDS,
    DeviceProfile,
    InvalidPayloadError,
    InvalidProfileError,
    SimulatedDevice,
    SimulatedReceiver,
    SimulationResult,
    SimulatorConfig,
    SimulatorTimeoutError,
    UnknownFlowError,
    create_device_event,
    serialize_device_event,
    simulate_device_round_trip,
)
from qeris.device_auth import DeviceAuthStatus, GatewayChallengeManager, verify_device_signature
from qeris.session_crypto import (
    CIPHERTEXT_LENGTH,
    PUBLIC_KEY_LENGTH,
    compute_handshake_id,
)
from qeris.hybrid_session_crypto import (
    CLIENT_KEY_SHARE_LENGTH,
    SERVER_KEY_SHARE_LENGTH,
    HYBRID_GROUP,
)


class TestDeviceSimulator(unittest.TestCase):
    """Test suite for the local in-process device-to-gateway simulator."""

    def test_successful_crypto_round_trip_and_matching_fingerprints(self):
        """Verify full round-trip: KEM keygen, encap, decap, HKDF derivation,

        matching SHA-256 fingerprints, AEAD message round-trip,
        and explicit reporting that gateway authorization remains outside this simulator.
        """
        result = simulate_device_round_trip()

        self.assertIsInstance(result, SimulationResult)
        self.assertTrue(result.success)
        self.assertTrue(result.fingerprints_match)
        self.assertTrue(result.received_payload_matches)

        # Cryptographic artifact lengths
        self.assertEqual(result.public_key_length, PUBLIC_KEY_LENGTH)
        self.assertEqual(result.ciphertext_length, CIPHERTEXT_LENGTH)
        self.assertGreater(result.envelope_length, 0)

        # Fingerprint properties (SHA-256 hex is 64 characters)
        self.assertEqual(len(result.shared_secret_fingerprint), 64)
        self.assertEqual(len(result.session_key_fingerprint), 64)

        # Handshake ID transcript hash
        self.assertEqual(len(result.handshake_id), 64)

        # Explicit security boundary reporting
        self.assertEqual(result.authorization_decision, "NOT_PERFORMED")
        self.assertIn("Authorization has not been performed", result.authorization_note)
        self.assertEqual(result.device_authentication_status, "SIGNING_PRIMITIVE_AVAILABLE_NOT_VERIFIED")
        self.assertIn("gateway registry verification is outside", result.device_authentication_note)

    def test_custom_payload_round_trip(self):
        """Verify custom payload and registered flow mapping round-trip."""
        custom_payload = b'{"sensor": "pressure", "reading_kpa": 101.325, "active": true}'
        device_id = "DEV-PRESSURE-007"
        flow_id = "FLOW-PRESSURE-02"

        result = simulate_device_round_trip(
            device_id=device_id,
            flow_id=flow_id,
            payload=custom_payload,
        )

        self.assertTrue(result.success)
        self.assertTrue(result.received_payload_matches)
        self.assertEqual(result.device_id, device_id)
        self.assertEqual(result.flow_id, flow_id)
        self.assertEqual(result.sensitivity_tier, "LOW")

        # Also verify custom flow tier map provided to receiver
        custom_map = {"FLOW-SPECIAL-99": "LOW"}
        custom_res = simulate_device_round_trip(
            device_id="DEV-SPECIAL-01",
            flow_id="FLOW-SPECIAL-99",
            payload=b"sensor-binary-data-\x00\xff",
            flow_tier_map=custom_map,
        )
        self.assertTrue(custom_res.success)
        self.assertTrue(custom_res.received_payload_matches)
        self.assertEqual(custom_res.sensitivity_tier, "LOW")

    def test_handshake_id_matching_and_correlation(self):
        """Verify device and receiver agree on handshake_id and correlate with compute_handshake_id."""
        device = SimulatedDevice("DEV-TEST-003")
        receiver = SimulatedReceiver()

        device_pk = device.generate_kem_keypair()
        ct, resolved_tier, p_version = receiver.handle_handshake(
            device_id="DEV-TEST-003",
            flow_id="FLOW-TEMP-01",
            device_public_key=device_pk,
        )
        device.complete_handshake(
            ciphertext=ct,
            flow_id="FLOW-TEMP-01",
            sensitivity_tier=resolved_tier,
            policy_version=p_version,
        )

        # Handshake ID exposed on both peers and matches
        self.assertIsNotNone(receiver.handshake_id)
        self.assertIsNotNone(device.handshake_id)
        self.assertEqual(receiver.handshake_id, device.handshake_id)
        self.assertEqual(len(receiver.handshake_id), 64)

        # Matches independent computation from primitive API
        expected_id = compute_handshake_id(
            device_pk,
            ct,
            device_id="DEV-TEST-003",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier=resolved_tier,
            policy_version=p_version,
        )
        self.assertEqual(receiver.handshake_id, expected_id)

    def test_simulated_device_ed25519_proof_of_possession(self):
        """Device signs its completed transcript with its separate long-term credential."""
        device = SimulatedDevice("DEV-ED25519-001")
        receiver = SimulatedReceiver()
        device_pk = device.generate_kem_keypair()
        ciphertext, tier, version = receiver.handle_handshake(
            device_id="DEV-ED25519-001", flow_id="FLOW-TEMP-01", device_public_key=device_pk
        )
        device.complete_handshake(ciphertext, "FLOW-TEMP-01", tier, version)
        challenge_manager = GatewayChallengeManager()
        challenge = challenge_manager.issue_challenge("DEV-ED25519-001")
        signature = device.sign_handshake_authentication(challenge.nonce, timestamp=int(challenge.issued_at))
        self.assertTrue(verify_device_signature(
            device_id="DEV-ED25519-001", handshake_id=device.handshake_id,
            challenge_nonce=challenge.nonce, timestamp=int(challenge.issued_at),
            signature=signature, enrolled_public_key_bytes=device.device_auth_public_key,
        ))
        self.assertEqual(len(device.device_auth_public_key), 32)
        self.assertEqual(len(signature), 64)
        self.assertEqual(
            challenge_manager.validate_and_consume("DEV-ED25519-001", challenge.nonce),
            DeviceAuthStatus.AUTH_SUCCESS,
        )

    def test_unknown_flow_rejection(self):
        """Verify that unrecognized flow identifiers fail closed with UnknownFlowError."""
        receiver = SimulatedReceiver()

        with self.assertRaises(UnknownFlowError):
            receiver.resolve_flow_tier("FLOW-UNREGISTERED-999")

        with self.assertRaises(UnknownFlowError):
            receiver.resolve_flow_tier("")

        with self.assertRaises(UnknownFlowError):
            simulate_device_round_trip(flow_id="FLOW-UNKNOWN-X")

    def test_invalid_payload_rejection(self):
        """Verify that non-bytes and empty payloads are rejected with InvalidPayloadError."""
        # Non-bytes payloads
        invalid_types = ["string-payload", 12345, None, ["list", "payload"], {"key": "val"}]
        for invalid_payload in invalid_types:
            with self.subTest(payload_type=type(invalid_payload).__name__):
                with self.assertRaises(InvalidPayloadError):
                    # Test at top-level orchestrator
                    simulate_device_round_trip(payload=invalid_payload)  # type: ignore[arg-type]

        # Empty bytes payload
        with self.assertRaises(InvalidPayloadError):
            simulate_device_round_trip(payload=b"")

        # Test at device method level directly
        device = SimulatedDevice("DEV-TEST-002")
        receiver = SimulatedReceiver()
        pk = device.generate_kem_keypair()
        ct, tier, p_ver = receiver.handle_handshake("DEV-TEST-002", "FLOW-TEMP-01", pk)
        device.complete_handshake(ct, "FLOW-TEMP-01", tier, p_ver)

        with self.assertRaises(InvalidPayloadError):
            device.send_telemetry(b"")

        with self.assertRaises(InvalidPayloadError):
            device.send_telemetry("not-bytes")  # type: ignore[arg-type]

    def test_classical_profile_round_trip(self):
        """Verify successful round-trip using CLASSICAL profile (X25519 + HKDF + AES-GCM)."""
        result = simulate_device_round_trip(profile=DeviceProfile.CLASSICAL)

        self.assertIsInstance(result, SimulationResult)
        self.assertTrue(result.success)
        self.assertTrue(result.fingerprints_match)
        self.assertTrue(result.received_payload_matches)
        self.assertEqual(result.profile, "CLASSICAL")

        # X25519 public key and peer public key token length are 32 bytes
        self.assertEqual(result.public_key_length, 32)
        self.assertEqual(result.ciphertext_length, 32)
        self.assertGreater(result.envelope_length, 0)

        # Non-secret fingerprints and deterministic correlation handshake_id
        self.assertEqual(len(result.shared_secret_fingerprint), 64)
        self.assertEqual(len(result.session_key_fingerprint), 64)
        self.assertEqual(len(result.handshake_id), 64)

    def test_pqc_profile_explicit_and_default_backward_compatibility(self):
        """Verify default profile is PQC and explicit PQC profile produces identical behavior."""
        default_res = simulate_device_round_trip()
        explicit_res = simulate_device_round_trip(profile=DeviceProfile.PQC)

        self.assertEqual(default_res.profile, "PQC")
        self.assertEqual(explicit_res.profile, "PQC")
        self.assertEqual(default_res.public_key_length, PUBLIC_KEY_LENGTH)
        self.assertEqual(explicit_res.public_key_length, PUBLIC_KEY_LENGTH)
        self.assertEqual(default_res.ciphertext_length, CIPHERTEXT_LENGTH)
        self.assertEqual(explicit_res.ciphertext_length, CIPHERTEXT_LENGTH)
        self.assertTrue(default_res.success)
        self.assertTrue(explicit_res.success)

    def test_invalid_profile_rejection(self):
        """Verify that raw string aliases and unknown profiles are rejected; enum profiles are required."""
        with self.assertRaises(InvalidProfileError):
            SimulatorConfig(profile="HYBRID")  # type: ignore[arg-type]

        with self.assertRaises(InvalidProfileError):
            SimulatorConfig(profile="UNKNOWN")  # type: ignore[arg-type]

        with self.assertRaises(InvalidProfileError):
            SimulatedReceiver(profile="HYBRID")  # type: ignore[arg-type]

        with self.assertRaises(InvalidProfileError):
            simulate_device_round_trip(profile="HYBRID")  # type: ignore[arg-type]

    def test_synthetic_delay_execution(self):
        """Verify that a small synthetic delay executes cleanly without timeout."""
        config = SimulatorConfig(
            profile=DeviceProfile.PQC,
            compute_delay_seconds=0.005,
            timeout_seconds=1.0,
        )
        res = simulate_device_round_trip(config=config)
        self.assertTrue(res.success)

    def test_synthetic_delay_timeout_simulation(self):
        """Verify that exceeding configured timeout raises SimulatorTimeoutError."""
        config = SimulatorConfig(
            profile=DeviceProfile.PQC,
            compute_delay_seconds=0.05,
            timeout_seconds=0.01,
        )
        with self.assertRaises(SimulatorTimeoutError):
            simulate_device_round_trip(config=config)

    def test_on_failure_callback_hook(self):
        """Verify that the on_failure callback receives phase and exception before re-raise."""
        captured_events: list[tuple[str, Exception]] = []

        def failure_hook(phase: str, exc: Exception) -> None:
            captured_events.append((phase, exc))

        config = SimulatorConfig(
            profile=DeviceProfile.PQC,
            compute_delay_seconds=0.05,
            timeout_seconds=0.01,
            on_failure=failure_hook,
        )

        with self.assertRaises(SimulatorTimeoutError):
            simulate_device_round_trip(config=config)

        self.assertEqual(len(captured_events), 1)
        phase, exc = captured_events[0]
        self.assertEqual(phase, "keypair_generation")
        self.assertIsInstance(exc, SimulatorTimeoutError)

    def test_classical_direct_device_and_receiver_flow(self):
        """Verify manual step-by-step usage of SimulatedDevice and SimulatedReceiver with CLASSICAL."""
        config = SimulatorConfig(profile=DeviceProfile.CLASSICAL)
        device = SimulatedDevice("DEV-CLASSICAL-01", config=config)
        receiver = SimulatedReceiver(profile=DeviceProfile.CLASSICAL)

        self.assertEqual(device.profile, DeviceProfile.CLASSICAL)
        self.assertEqual(receiver.profile, DeviceProfile.CLASSICAL)

        # Receiver generates its ephemeral public key
        rec_pub = receiver.generate_classical_ephemeral()
        self.assertEqual(len(rec_pub), 32)

        # Device generates ephemeral keypair
        dev_pub = device.generate_kem_keypair()
        self.assertEqual(len(dev_pub), 32)

        # Receiver processes handshake
        handshake_token, tier, p_ver = receiver.handle_handshake(
            "DEV-CLASSICAL-01", "FLOW-TEMP-01", dev_pub
        )
        self.assertEqual(handshake_token, rec_pub)

        # Device completes handshake
        device.complete_handshake(
            rec_pub, "FLOW-TEMP-01", tier, p_ver,
            receiver_handshake_id=receiver.handshake_id,
        )

        # Verify fingerprints and handshake ID agreement
        self.assertEqual(device.shared_secret_fingerprint, receiver.shared_secret_fingerprint)
        self.assertEqual(device.session_key_fingerprint, receiver.session_key_fingerprint)
        self.assertEqual(device.handshake_id, receiver.handshake_id)

        # Encrypt and decrypt telemetry
        payload = b"sensor-data-classical"
        envelope = device.send_telemetry(payload)
        decrypted = receiver.receive_telemetry(envelope)
        self.assertEqual(decrypted, payload)


class TestHybridDeviceProfile(unittest.TestCase):
    """Tests for the in-process X25519MLKEM768 hybrid simulator profile."""

    def test_hybrid_profile_round_trip_and_share_lengths(self):
        result = simulate_device_round_trip(profile=DeviceProfile.HYBRID)

        self.assertIsInstance(result, SimulationResult)
        self.assertTrue(result.success)
        self.assertTrue(result.fingerprints_match)
        self.assertTrue(result.received_payload_matches)
        self.assertEqual(result.profile, "HYBRID")
        self.assertEqual(HYBRID_GROUP, "X25519MLKEM768")
        self.assertEqual(result.public_key_length, CLIENT_KEY_SHARE_LENGTH)
        self.assertEqual(result.public_key_length, 1216)
        self.assertEqual(result.ciphertext_length, SERVER_KEY_SHARE_LENGTH)
        self.assertEqual(result.ciphertext_length, 1120)
        self.assertEqual(len(result.shared_secret_fingerprint), 64)
        self.assertEqual(len(result.session_key_fingerprint), 64)
        self.assertEqual(len(result.handshake_id), 64)

    def test_hybrid_direct_device_receiver_exchange_and_telemetry(self):
        config = SimulatorConfig(profile=DeviceProfile.HYBRID)
        device = SimulatedDevice("DEV-HYBRID-001", config=config)
        receiver = SimulatedReceiver(profile=DeviceProfile.HYBRID)

        client_share = device.generate_kem_keypair()
        self.assertEqual(len(client_share), 1216)

        server_share, tier, version = receiver.handle_handshake(
            "DEV-HYBRID-001", "FLOW-TEMP-01", client_share
        )
        self.assertEqual(len(server_share), 1120)

        device.complete_handshake(
            server_share,
            "FLOW-TEMP-01",
            tier,
            version,
            receiver_handshake_id=receiver.handshake_id,
        )

        self.assertEqual(device.shared_secret_fingerprint, receiver.shared_secret_fingerprint)
        self.assertEqual(device.session_key_fingerprint, receiver.session_key_fingerprint)
        self.assertEqual(device.handshake_id, receiver.handshake_id)

        payload = b'{"hybrid": true, "temperature": 21.5}'
        envelope = device.send_telemetry(payload)
        self.assertEqual(receiver.receive_telemetry(envelope), payload)

    def test_hybrid_profile_has_distinct_parameter_sizes_from_existing_pqc(self):
        hybrid = simulate_device_round_trip(profile=DeviceProfile.HYBRID)
        pqc = simulate_device_round_trip(profile=DeviceProfile.PQC)

        self.assertEqual(hybrid.public_key_length, 1216)
        self.assertEqual(hybrid.ciphertext_length, 1120)
        self.assertEqual(pqc.public_key_length, 800)
        self.assertEqual(pqc.ciphertext_length, 768)
        self.assertNotEqual(hybrid.session_key_fingerprint, pqc.session_key_fingerprint)

    def test_hybrid_synthetic_timeout_uses_existing_failure_contract(self):
        config = SimulatorConfig(
            profile=DeviceProfile.HYBRID,
            compute_delay_seconds=0.05,
            timeout_seconds=0.01,
        )
        with self.assertRaises(SimulatorTimeoutError):
            simulate_device_round_trip(config=config)

    def test_hybrid_profile_rejects_string_alias_without_enum(self):
        with self.assertRaises(InvalidProfileError):
            SimulatorConfig(profile="HYBRID")  # type: ignore[arg-type]


class TestDeviceEventLogging(unittest.TestCase):
    """Test suite for S1 structured device event logging."""

    def test_event_fields_and_types(self):
        """Verify all 8 agreed fields exist with exact expected types."""
        event = create_device_event(
            device_id="DEV-TEST-001",
            flow_id="FLOW-TEMP-01",
            event="connection_start",
            mode="PQC",
            cause="none",
            size_bytes=800,
            duration_ms=1.234,
        )

        self.assertEqual(set(event.keys()), set(STRUCTURED_DEVICE_EVENT_FIELDS))
        self.assertIsInstance(event["ts"], int)
        self.assertIsInstance(event["device_id"], str)
        self.assertIsInstance(event["flow_id"], str)
        self.assertIsInstance(event["event"], str)
        self.assertIsInstance(event["mode"], str)
        self.assertIsInstance(event["cause"], str)
        self.assertIsInstance(event["size_bytes"], int)
        self.assertIsInstance(event["duration_ms"], float)

    def test_event_json_serialization(self):
        """Verify canonical JSON serialization round-trips correctly."""
        event = create_device_event(
            device_id="DEV-TEST-001",
            flow_id="FLOW-TEMP-01",
            event="handshake_complete",
            mode="HYBRID",
            cause="none",
            size_bytes=1120,
            duration_ms=2.5,
        )
        serialized = serialize_device_event(event)
        self.assertIsInstance(serialized, str)

        parsed = json.loads(serialized)
        self.assertEqual(parsed, event)
        self.assertEqual(set(parsed.keys()), set(STRUCTURED_DEVICE_EVENT_FIELDS))

    def test_event_lifecycle_coverage_all_profiles(self):
        """Verify connection_start, handshake_complete, and data_sent events for PQC, CLASSICAL, and HYBRID."""
        for profile in (DeviceProfile.PQC, DeviceProfile.CLASSICAL, DeviceProfile.HYBRID):
            with self.subTest(profile=profile.value):
                result = simulate_device_round_trip(profile=profile)
                self.assertTrue(result.success)
                self.assertIsInstance(result.events, tuple)
                self.assertEqual(len(result.events), 3)

                ev_start, ev_complete, ev_data = result.events

                self.assertEqual(ev_start["event"], "connection_start")
                self.assertEqual(ev_start["mode"], profile.value)
                self.assertEqual(ev_start["size_bytes"], result.public_key_length)
                self.assertEqual(ev_start["cause"], "none")

                self.assertEqual(ev_complete["event"], "handshake_complete")
                self.assertEqual(ev_complete["mode"], profile.value)
                self.assertEqual(ev_complete["size_bytes"], result.public_key_length + result.ciphertext_length)
                self.assertEqual(ev_complete["cause"], "none")

                self.assertEqual(ev_data["event"], "data_sent")
                self.assertEqual(ev_data["mode"], profile.value)
                self.assertEqual(ev_data["size_bytes"], result.envelope_length)
                self.assertEqual(ev_data["cause"], "none")

    def test_event_hook_invocation(self):
        """Verify SimulatorConfig event_hook receives each event in sequence."""
        captured: list[dict[str, Any]] = []
        config = SimulatorConfig(
            profile=DeviceProfile.PQC,
            event_hook=captured.append,
        )
        result = simulate_device_round_trip(config=config)

        self.assertEqual(len(captured), 3)
        self.assertEqual(tuple(captured), result.events)

    def test_failure_event_emission_on_timeout(self):
        """Verify a failure event is emitted with cause when a timeout occurs."""
        captured: list[dict[str, Any]] = []
        config = SimulatorConfig(
            profile=DeviceProfile.PQC,
            compute_delay_seconds=0.05,
            timeout_seconds=0.01,
            event_hook=captured.append,
        )
        with self.assertRaises(SimulatorTimeoutError):
            simulate_device_round_trip(config=config)

        self.assertGreaterEqual(len(captured), 1)
        fail_events = [ev for ev in captured if ev["event"] == "failure"]
        self.assertEqual(len(fail_events), 1)
        self.assertEqual(fail_events[0]["cause"], "timeout")
        self.assertEqual(fail_events[0]["mode"], "PQC")

    def test_failure_event_emission_on_invalid_payload(self):
        """Verify a failure event is emitted when an invalid payload is provided."""
        captured: list[dict[str, Any]] = []
        config = SimulatorConfig(
            profile=DeviceProfile.CLASSICAL,
            event_hook=captured.append,
        )
        with self.assertRaises(InvalidPayloadError):
            simulate_device_round_trip(
                payload="not-bytes",  # type: ignore[arg-type]
                config=config,
            )

        fail_events = [ev for ev in captured if ev["event"] == "failure"]
        self.assertEqual(len(fail_events), 1)
        self.assertEqual(fail_events[0]["cause"], "invalid_payload")
        self.assertEqual(fail_events[0]["mode"], "CLASSICAL")

    def test_secret_exclusion_in_events(self):
        """Verify that no sensitive key material or secrets are present in events."""
        forbidden_substrings = [
            "secret",
            "private",
            "seed",
            "sensitive",
            "plaintext",
        ]
        test_payload = b"SECRET_PLAINTEXT_TELEMETRY_PAYLOAD_12345"

        captured: list[dict[str, Any]] = []
        config = SimulatorConfig(
            profile=DeviceProfile.HYBRID,
            event_hook=captured.append,
        )
        result = simulate_device_round_trip(payload=test_payload, config=config)
        self.assertTrue(result.success)

        for event in captured:
            # Check keys strictly match allowed fields
            self.assertEqual(set(event.keys()), set(STRUCTURED_DEVICE_EVENT_FIELDS))

            # Check JSON string for any leakage
            serialized = serialize_device_event(event)
            self.assertNotIn("SECRET_PLAINTEXT", serialized)
            for sub in forbidden_substrings:
                self.assertNotIn(sub, serialized.lower())

    def test_device_events_property_immutability(self):
        """Verify device.events returns an immutable tuple."""
        device = SimulatedDevice("DEV-001", config=SimulatorConfig(profile=DeviceProfile.PQC))
        self.assertIsInstance(device.events, tuple)


if __name__ == "__main__":
    unittest.main()
