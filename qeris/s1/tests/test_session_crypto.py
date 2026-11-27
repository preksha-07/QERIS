"""Real-crypto tests for QERIS Step 2; no mocks or production keys."""
import hashlib
import unittest

import oqs

from qeris.session_crypto import (
    CIPHERTEXT_LENGTH,
    HANDSHAKE_TRANSCRIPT_LABEL,
    KEM_ALGORITHM,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    CryptoInputError,
    compute_handshake_id,
    compute_transcript_hash,
    decapsulate,
    derive_session_key,
    encapsulate,
    encode_handshake_transcript,
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

    def test_handshake_id_deterministic_for_identical_inputs(self):
        pk, _ = generate_keypair()
        ct, _ = encapsulate(pk)
        params = dict(
            device_id="device-001",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        id1 = compute_handshake_id(pk, ct, **params)
        id2 = compute_handshake_id(pk, ct, **params)
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 64)
        # Check hex character validity
        self.assertEqual(id1, id1.lower())
        int(id1, 16)  # must not raise ValueError

        # Check raw hash matches hex representation
        raw_hash = compute_transcript_hash(pk, ct, **params)
        self.assertEqual(len(raw_hash), 32)
        self.assertEqual(raw_hash.hex(), id1)

        # Check transcript encoding contains the domain label
        transcript = encode_handshake_transcript(pk, ct, **params)
        self.assertTrue(transcript.startswith(HANDSHAKE_TRANSCRIPT_LABEL))
        self.assertEqual(hashlib.sha256(transcript).hexdigest(), id1)

    def test_handshake_id_changes_when_public_key_changes(self):
        pk1, _ = generate_keypair()
        pk2, _ = generate_keypair()
        ct, _ = encapsulate(pk1)
        params = dict(
            device_id="device-001",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        id1 = compute_handshake_id(pk1, ct, **params)
        id2 = compute_handshake_id(pk2, ct, **params)
        self.assertNotEqual(id1, id2)

    def test_handshake_id_changes_when_ciphertext_changes(self):
        pk, _ = generate_keypair()
        ct1, _ = encapsulate(pk)
        ct2, _ = encapsulate(pk)
        params = dict(
            device_id="device-001",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        id1 = compute_handshake_id(pk, ct1, **params)
        id2 = compute_handshake_id(pk, ct2, **params)
        self.assertNotEqual(id1, id2)

        # Single bit flip in ciphertext
        ct_tampered = bytearray(ct1)
        ct_tampered[0] ^= 1
        id_tampered = compute_handshake_id(pk, bytes(ct_tampered), **params)
        self.assertNotEqual(id1, id_tampered)

    def test_handshake_id_changes_when_any_context_field_changes(self):
        pk, _ = generate_keypair()
        ct, _ = encapsulate(pk)
        base = dict(
            device_id="device-001",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        base_id = compute_handshake_id(pk, ct, **base)

        # Change device_id
        diff_dev = compute_handshake_id(pk, ct, **dict(base, device_id="device-002"))
        self.assertNotEqual(base_id, diff_dev)

        # Change flow_id
        diff_flow = compute_handshake_id(pk, ct, **dict(base, flow_id="FLOW-TEMP-02"))
        self.assertNotEqual(base_id, diff_flow)

        # Change sensitivity_tier
        diff_tier = compute_handshake_id(pk, ct, **dict(base, sensitivity_tier="HIGH"))
        self.assertNotEqual(base_id, diff_tier)

        # Change policy_version
        diff_ver = compute_handshake_id(pk, ct, **dict(base, policy_version=2))
        self.assertNotEqual(base_id, diff_ver)

    def test_handshake_id_rejects_malformed_inputs(self):
        pk, _ = generate_keypair()
        ct, _ = encapsulate(pk)
        valid = dict(
            device_id="device-001",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )

        # Malformed public key
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(b"short", ct, **valid)
        with self.assertRaises(TypeError):
            compute_handshake_id("not-bytes", ct, **valid)  # type: ignore[arg-type]

        # Malformed ciphertext
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, b"short", **valid)
        with self.assertRaises(TypeError):
            compute_handshake_id(pk, "not-bytes", **valid)  # type: ignore[arg-type]

        # Malformed context fields
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, device_id=""))
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, flow_id="   "))
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, sensitivity_tier=""))
        with self.assertRaises(TypeError):
            compute_handshake_id(pk, ct, **dict(valid, device_id=123))  # type: ignore[arg-type]

        # Malformed policy_version
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, policy_version=True))
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, policy_version=0))
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, policy_version=-5))
        with self.assertRaises(CryptoInputError):
            compute_handshake_id(pk, ct, **dict(valid, policy_version="1"))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main(verbosity=2)
