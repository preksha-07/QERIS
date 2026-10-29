"""Real-crypto tests for QERIS Step 2; no mocks or production keys."""
import unittest

import oqs

from qeris.session_crypto import (
    CIPHERTEXT_LENGTH,
    KEM_ALGORITHM,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    CryptoInputError,
    decapsulate,
    derive_session_key,
    encapsulate,
    generate_keypair,
    shared_secret_fingerprint,
)


class TestQERISSessionCrypto(unittest.TestCase):
    def test_ml_kem_512_is_enabled(self):
        self.assertIn(KEM_ALGORITHM, oqs.get_enabled_kem_mechanisms())

    def test_real_encapsulation_and_decapsulation_match(self):
        public_key, secret_key = generate_keypair()
        ciphertext, sender_secret = encapsulate(public_key)
        receiver_secret = decapsulate(ciphertext, secret_key)
        self.assertEqual(sender_secret, receiver_secret)
        self.assertEqual(
            shared_secret_fingerprint(sender_secret),
            shared_secret_fingerprint(receiver_secret),
        )

    def test_generated_key_and_ciphertext_lengths(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared_secret = encapsulate(public_key)
        self.assertEqual(len(public_key), PUBLIC_KEY_LENGTH)
        self.assertEqual(len(secret_key), SECRET_KEY_LENGTH)
        self.assertEqual(len(ciphertext), CIPHERTEXT_LENGTH)
        self.assertEqual(len(shared_secret), 32)

    def test_bad_lengths_are_rejected_before_liboqs(self):
        with self.assertRaises(CryptoInputError):
            encapsulate(b"short")
        with self.assertRaises(CryptoInputError):
            decapsulate(b"short", b"x" * SECRET_KEY_LENGTH)
        with self.assertRaises(CryptoInputError):
            decapsulate(b"x" * CIPHERTEXT_LENGTH, b"short")

    def test_one_bit_ciphertext_change_does_not_match_original_secret(self):
        public_key, secret_key = generate_keypair()
        ciphertext, sender_secret = encapsulate(public_key)
        changed = bytearray(ciphertext)
        changed[0] ^= 1
        changed_secret = decapsulate(bytes(changed), secret_key)
        # ML-KEM implementations commonly use implicit rejection: a modified
        # valid-length ciphertext may yield a pseudorandom secret, not an error.
        self.assertNotEqual(
            shared_secret_fingerprint(sender_secret),
            shared_secret_fingerprint(changed_secret),
        )

    def test_context_changes_derived_key(self):
        _, secret_key = generate_keypair()
        _, shared_secret = encapsulate(generate_keypair()[0])
        base = dict(
            device_id="device-001",
            flow_id="temperature",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        key_a = derive_session_key(shared_secret, **base)
        changed_flow = dict(base, flow_id="actuator-command")
        key_b = derive_session_key(shared_secret, **changed_flow)
        changed_tier = dict(base, sensitivity_tier="HIGH")
        key_c = derive_session_key(shared_secret, **changed_tier)
        changed_version = dict(base, policy_version=2)
        key_d = derive_session_key(shared_secret, **changed_version)
        changed_device = dict(base, device_id="device-002")
        key_e = derive_session_key(shared_secret, **changed_device)
        self.assertEqual(len(key_a), 32)
        self.assertNotEqual(key_a, key_b)
        self.assertNotEqual(key_a, key_c)
        self.assertNotEqual(key_a, key_d)
        self.assertNotEqual(key_a, key_e)

    def test_invalid_context_is_rejected(self):
        _, shared_secret = encapsulate(generate_keypair()[0])
        with self.assertRaises(CryptoInputError):
            derive_session_key(
                shared_secret,
                device_id="device",
                flow_id="flow",
                sensitivity_tier="LOW",
                policy_version=True,
            )
        with self.assertRaises(CryptoInputError):
            derive_session_key(
                shared_secret,
                device_id="device",
                flow_id=" ",
                sensitivity_tier="LOW",
                policy_version=1,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
