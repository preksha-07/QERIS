import unittest

from qeris_classical import (
    AuthenticationError,
    ClassicalCryptoInputError,
    ReplayError,
    UnsupportedCryptoModeError,
    derive_session_key,
    derive_shared_secret,
    establish_session,
    generate_keypair,
)


class X25519Tests(unittest.TestCase):
    def test_both_parties_derive_same_shared_secret(self):
        public_a, private_a = generate_keypair()
        public_b, private_b = generate_keypair()
        self.assertEqual(
            derive_shared_secret(private_a, public_b),
            derive_shared_secret(private_b, public_a),
        )

    def test_wrong_key_lengths_rejected(self):
        with self.assertRaises(ClassicalCryptoInputError):
            derive_shared_secret(b"short", b"x" * 32)
        with self.assertRaises(ClassicalCryptoInputError):
            derive_shared_secret(b"x" * 32, b"short")

    def test_context_changes_derived_key(self):
        public_a, private_a = generate_keypair()
        public_b, private_b = generate_keypair()
        shared = derive_shared_secret(private_a, public_b)
        key_one = derive_session_key(
            shared, device_id="device-1", flow_id="temperature_01",
            sensitivity_tier="LOW", policy_version=1,
        )
        key_two = derive_session_key(
            shared, device_id="device-1", flow_id="pressure_01",
            sensitivity_tier="LOW", policy_version=1,
        )
        self.assertEqual(len(key_one), 32)
        self.assertNotEqual(key_one, key_two)


class ClassicalSessionTests(unittest.TestCase):
    def setUp(self):
        self.session = establish_session(
            device_id="ESP32_NODE_01",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
        )

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"QERIS classical-mode demonstration payload"
        envelope = self.session.encrypt(plaintext)
        self.assertEqual(self.session.decrypt(envelope), plaintext)
        self.assertEqual(self.session.mode, "CLASSICAL")
        self.assertEqual(self.session.key_exchange, "X25519")

    def test_replay_is_rejected(self):
        envelope = self.session.encrypt(b"one message")
        self.assertEqual(self.session.decrypt(envelope), b"one message")
        with self.assertRaises(ReplayError):
            self.session.decrypt(envelope)

    def test_tampering_is_rejected(self):
        envelope = bytearray(self.session.encrypt(b"authenticated message"))
        envelope[-1] ^= 0x01
        with self.assertRaises(AuthenticationError):
            self.session.decrypt(bytes(envelope))

    def test_wrong_context_is_rejected(self):
        other = establish_session(
            device_id="ESP32_NODE_02",
            flow_id="temperature_01",
            sensitivity="LOW",
            policy_version=1,
        )
        envelope = self.session.encrypt(b"bound to original device")
        with self.assertRaises(AuthenticationError):
            other.decrypt(envelope)

    def test_non_classical_modes_are_not_claimed_supported(self):
        for mode in ("PQC", "HYBRID", "unknown"):
            with self.subTest(mode=mode):
                with self.assertRaises(UnsupportedCryptoModeError):
                    establish_session("device", "flow", "LOW", 1, mode=mode)

    def test_invalid_policy_context_is_rejected(self):
        with self.assertRaises(Exception):
            establish_session("device", "flow", "LOW", True)


if __name__ == "__main__":
    unittest.main()
