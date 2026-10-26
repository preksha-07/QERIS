"""Tests for QERIS Step 4: Local In-Process Device Simulator."""

import unittest

from qeris.device_simulator import (
    InvalidPayloadError,
    SimulatedDevice,
    SimulatedReceiver,
    SimulationResult,
    UnknownFlowError,
    simulate_device_round_trip,
)
from qeris.session_crypto import CIPHERTEXT_LENGTH, PUBLIC_KEY_LENGTH


class TestDeviceSimulator(unittest.TestCase):
    """Test suite for the local in-process device-to-gateway simulator."""

    def test_successful_crypto_round_trip_and_matching_fingerprints(self):
        """Verify full round-trip: KEM keygen, encap, decap, HKDF derivation,

        matching SHA-256 fingerprints, AEAD message round-trip,
        and explicit reporting of NOT_PERFORMED and NOT_IMPLEMENTED boundaries.
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

        # Explicit security boundary reporting
        self.assertEqual(result.authorization_decision, "NOT_PERFORMED")
        self.assertIn("Authorization has not been performed", result.authorization_note)
        self.assertEqual(result.device_authentication_status, "NOT_IMPLEMENTED")
        self.assertIn("Device authentication is unresolved", result.device_authentication_note)

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


if __name__ == "__main__":
    unittest.main()
