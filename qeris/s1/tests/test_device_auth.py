"""Unit tests for QERIS S1: Ed25519 Device Authentication."""

import time
import unittest

from qeris.s1.qeris.device_auth import (
    CHALLENGE_NONCE_LENGTH,
    DEFAULT_CHALLENGE_TTL_SECONDS,
    DEVICE_AUTH_DOMAIN_SEPARATOR,
    DeviceAuthResult,
    DeviceAuthStatus,
    Ed25519DeviceCredential,
    FreshnessChallenge,
    GatewayChallengeManager,
    build_canonical_device_auth_message,
    verify_device_signature,
)


class TestEd25519DeviceAuth(unittest.TestCase):
    def setUp(self):
        self.device_id = "DEV-TEST-001"
        self.handshake_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        self.cred = Ed25519DeviceCredential()
        self.challenge_mgr = GatewayChallengeManager(ttl_seconds=30.0)
        self.challenge = self.challenge_mgr.issue_challenge(self.device_id)

    def test_credential_generation_and_lengths(self):
        """Verify Ed25519 public key has standard 32 bytes and 64-char hex."""
        self.assertEqual(len(self.cred.public_key_bytes), 32)
        self.assertEqual(len(self.cred.public_key_hex), 64)
        # Verify hex format
        self.assertEqual(self.cred.public_key_hex, self.cred.public_key_bytes.hex())

    def test_private_key_confidentiality(self):
        """Verify private key is never exposed in repr or str."""
        rep = repr(self.cred)
        str_val = str(self.cred)
        self.assertIn("secret redacted", rep)
        self.assertIn("secret redacted", str_val)
        self.assertNotIn(self.cred.public_key_bytes.hex(), rep)

    def test_valid_authentication_round_trip(self):
        """Verify valid signature passes verification."""
        ts = int(time.time())
        sig = self.cred.sign_authentication_message(
            device_id=self.device_id,
            handshake_id=self.handshake_id,
            challenge_nonce=self.challenge.nonce,
            timestamp=ts,
        )
        self.assertEqual(len(sig), 64)

        is_valid = verify_device_signature(
            device_id=self.device_id,
            handshake_id=self.handshake_id,
            challenge_nonce=self.challenge.nonce,
            timestamp=ts,
            signature=sig,
            enrolled_public_key_bytes=self.cred.public_key_bytes,
        )
        self.assertTrue(is_valid)

    def test_tampered_signature_rejected(self):
        """Verify flipped bit in signature fails verification."""
        ts = int(time.time())
        sig = bytearray(
            self.cred.sign_authentication_message(
                device_id=self.device_id,
                handshake_id=self.handshake_id,
                challenge_nonce=self.challenge.nonce,
                timestamp=ts,
            )
        )
        sig[0] ^= 0xFF  # Corrupt signature

        is_valid = verify_device_signature(
            device_id=self.device_id,
            handshake_id=self.handshake_id,
            challenge_nonce=self.challenge.nonce,
            timestamp=ts,
            signature=bytes(sig),
            enrolled_public_key_bytes=self.cred.public_key_bytes,
        )
        self.assertFalse(is_valid)

    def test_mismatched_handshake_id_rejected(self):
        """Verify signature over one handshake_id cannot authenticate another."""
        ts = int(time.time())
        sig = self.cred.sign_authentication_message(
            device_id=self.device_id,
            handshake_id=self.handshake_id,
            challenge_nonce=self.challenge.nonce,
            timestamp=ts,
        )
        wrong_hid = "0000000000000000000000000000000000000000000000000000000000000000"

        is_valid = verify_device_signature(
            device_id=self.device_id,
            handshake_id=wrong_hid,
            challenge_nonce=self.challenge.nonce,
            timestamp=ts,
            signature=sig,
            enrolled_public_key_bytes=self.cred.public_key_bytes,
        )
        self.assertFalse(is_valid)

    def test_challenge_single_use_prevents_replay(self):
        """Verify challenge cannot be used more than once."""
        status1 = self.challenge_mgr.validate_and_consume(
            self.device_id, self.challenge.nonce
        )
        self.assertEqual(status1, DeviceAuthStatus.AUTH_SUCCESS)

        # Attempt to replay the exact same challenge
        status2 = self.challenge_mgr.validate_and_consume(
            self.device_id, self.challenge.nonce
        )
        self.assertEqual(status2, DeviceAuthStatus.AUTH_CHALLENGE_REPLAYED)

    def test_expired_challenge_rejected(self):
        """Verify challenge past TTL is rejected."""
        short_mgr = GatewayChallengeManager(ttl_seconds=1.0)
        ch = short_mgr.issue_challenge(self.device_id)

        # Simulate time passing beyond expiry
        future_time = time.time() + 10.0
        status = short_mgr.validate_and_consume(
            self.device_id, ch.nonce, current_time=future_time
        )
        self.assertEqual(status, DeviceAuthStatus.AUTH_CHALLENGE_EXPIRED)

    def test_device_binding_mismatch_rejected(self):
        """Verify challenge issued for device A cannot be used by device B."""
        status = self.challenge_mgr.validate_and_consume(
            "DEV-ATTACKER-999", self.challenge.nonce
        )
        self.assertEqual(status, DeviceAuthStatus.AUTH_MALFORMED)

    def test_domain_separation_label(self):
        """Verify domain separation label in canonical encoding."""
        msg = build_canonical_device_auth_message(
            device_id=self.device_id,
            handshake_id=self.handshake_id,
            challenge_nonce=self.challenge.nonce,
            timestamp=123456789,
        )
        self.assertEqual(len(DEVICE_AUTH_DOMAIN_SEPARATOR), 21)
        self.assertTrue(msg.startswith(b"\x00\x00\x00\x15" + DEVICE_AUTH_DOMAIN_SEPARATOR))

    def test_malformed_handshake_id_rejected_before_signing(self):
        with self.assertRaises(ValueError):
            self.cred.sign_authentication_message(
                device_id=self.device_id, handshake_id="not-a-sha256-id",
                challenge_nonce=self.challenge.nonce, timestamp=1234567890,
            )

    def test_wrong_challenge_length_rejected(self):
        with self.assertRaises(ValueError):
            build_canonical_device_auth_message(
                device_id=self.device_id, handshake_id=self.handshake_id,
                challenge_nonce=b"short", timestamp=1234567890,
            )

    def test_non_integer_timestamp_rejected(self):
        with self.assertRaises(TypeError):
            build_canonical_device_auth_message(
                device_id=self.device_id, handshake_id=self.handshake_id,
                challenge_nonce=self.challenge.nonce, timestamp="123",
            )


if __name__ == "__main__":
    unittest.main()
