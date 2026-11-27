"""Tests for the QERIS in-process X25519MLKEM768 Hybrid profile.

The tests exercise real liboqs ML-KEM-768 and the existing X25519 provider.
They validate the RFC 10024 component-share ordering and RFC 9954
concatenated shared-secret composition. They do NOT claim TLS/DTLS
interoperability.
"""
import unittest

import oqs

from qeris_classical.session_crypto import derive_shared_secret as x25519_derive_shared_secret

from qeris.hybrid_session_crypto import (
    CLIENT_KEY_SHARE_LENGTH,
    SERVER_KEY_SHARE_LENGTH,
    COMBINED_SHARED_SECRET_LENGTH,
    HYBRID_GROUP,
    MLKEM_ALGORITHM,
    MLKEM768_PUBLIC_KEY_LENGTH,
    MLKEM768_CIPHERTEXT_LENGTH,
    HybridCryptoInputError,
    compute_hybrid_handshake_id,
    decapsulate_hybrid,
    derive_hybrid_session_key,
    encapsulate_hybrid,
    generate_hybrid_keypair,
)


class TestHybridSessionCrypto(unittest.TestCase):
    def setUp(self):
        self.keypair = generate_hybrid_keypair()

    def test_hybrid_group_and_client_server_share_sizes(self):
        self.assertEqual(HYBRID_GROUP, "X25519MLKEM768")
        self.assertEqual(len(self.keypair.client_key_share), CLIENT_KEY_SHARE_LENGTH)
        self.assertEqual(CLIENT_KEY_SHARE_LENGTH, 1216)
        self.assertEqual(
            self.keypair.client_key_share[:MLKEM768_PUBLIC_KEY_LENGTH],
            self.keypair.mlkem_public_key,
        )
        self.assertEqual(
            self.keypair.client_key_share[MLKEM768_PUBLIC_KEY_LENGTH:],
            self.keypair.x25519_public_key,
        )

        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        self.assertEqual(len(encapsulation.server_key_share), SERVER_KEY_SHARE_LENGTH)
        self.assertEqual(SERVER_KEY_SHARE_LENGTH, 1120)
        self.assertEqual(
            len(encapsulation.combined_shared_secret),
            COMBINED_SHARED_SECRET_LENGTH,
        )
        self.assertEqual(COMBINED_SHARED_SECRET_LENGTH, 64)

    def test_client_and_server_derive_identical_combined_secret(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        client_secret = decapsulate_hybrid(
            encapsulation.server_key_share, self.keypair
        )
        self.assertEqual(client_secret, encapsulation.combined_shared_secret)
        self.assertEqual(len(client_secret), 64)

    def test_combined_secret_uses_mlkem_then_x25519_order(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        mlkem_ciphertext = encapsulation.server_key_share[:MLKEM768_CIPHERTEXT_LENGTH]
        server_x25519_public = encapsulation.server_key_share[MLKEM768_CIPHERTEXT_LENGTH:]

        kem = oqs.KeyEncapsulation(
            MLKEM_ALGORITHM, secret_key=self.keypair.mlkem_secret_key
        )
        try:
            expected_mlkem_secret = bytes(kem.decap_secret(mlkem_ciphertext))
        finally:
            kem.free()

        expected_x25519_secret = x25519_derive_shared_secret(
            self.keypair.x25519_private_key,
            server_x25519_public,
        )
        self.assertEqual(
            encapsulation.combined_shared_secret,
            expected_mlkem_secret + expected_x25519_secret,
        )

    def test_hybrid_session_key_is_context_bound(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        ikm = encapsulation.combined_shared_secret
        shared_context = dict(
            device_id="DEV-HYBRID-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        transcript_a = compute_hybrid_handshake_id(
            self.keypair.client_key_share,
            encapsulation.server_key_share,
            flow_id="FLOW-TEMP-01",
            **shared_context,
        )
        transcript_b = compute_hybrid_handshake_id(
            self.keypair.client_key_share,
            encapsulation.server_key_share,
            flow_id="FLOW-PRESSURE-02",
            **shared_context,
        )
        key_a = derive_hybrid_session_key(
            ikm,
            flow_id="FLOW-TEMP-01",
            handshake_id=transcript_a,
            **shared_context,
        )
        key_b = derive_hybrid_session_key(
            ikm,
            flow_id="FLOW-PRESSURE-02",
            handshake_id=transcript_b,
            **shared_context,
        )
        self.assertEqual(len(key_a), 32)
        self.assertNotEqual(key_a, key_b)
        self.assertNotEqual(transcript_a, transcript_b)

    def test_hybrid_handshake_id_binds_both_complete_shares(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        kwargs = dict(
            device_id="DEV-HYBRID-01",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        original = compute_hybrid_handshake_id(
            self.keypair.client_key_share,
            encapsulation.server_key_share,
            **kwargs,
        )
        changed_client = bytearray(self.keypair.client_key_share)
        changed_client[-1] ^= 0x01
        changed_server = bytearray(encapsulation.server_key_share)
        changed_server[-1] ^= 0x01
        self.assertNotEqual(
            original,
            compute_hybrid_handshake_id(bytes(changed_client), encapsulation.server_key_share, **kwargs),
        )
        self.assertNotEqual(
            original,
            compute_hybrid_handshake_id(self.keypair.client_key_share, bytes(changed_server), **kwargs),
        )
        self.assertEqual(len(original), 64)


    def test_hybrid_session_key_binds_handshake_transcript(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        context = dict(
            device_id="DEV-HYBRID-01",
            flow_id="FLOW-TEMP-01",
            sensitivity_tier="LOW",
            policy_version=1,
        )
        transcript_id = compute_hybrid_handshake_id(
            self.keypair.client_key_share,
            encapsulation.server_key_share,
            **context,
        )
        original = derive_hybrid_session_key(
            encapsulation.combined_shared_secret,
            handshake_id=transcript_id,
            **context,
        )
        alternate = derive_hybrid_session_key(
            encapsulation.combined_shared_secret,
            handshake_id="00" * 32,
            **context,
        )
        self.assertNotEqual(original, alternate)

    def test_hybrid_session_key_rejects_malformed_handshake_id(self):
        encapsulation = encapsulate_hybrid(self.keypair.client_key_share)
        with self.assertRaises(HybridCryptoInputError):
            derive_hybrid_session_key(
                encapsulation.combined_shared_secret,
                device_id="DEV-HYBRID-01",
                flow_id="FLOW-TEMP-01",
                sensitivity_tier="LOW",
                policy_version=1,
                handshake_id="not-a-digest",
            )

    def test_wrong_length_client_share_is_rejected(self):
        with self.assertRaises(HybridCryptoInputError):
            encapsulate_hybrid(b"\x00" * (CLIENT_KEY_SHARE_LENGTH - 1))

    def test_wrong_length_server_share_is_rejected(self):
        with self.assertRaises(HybridCryptoInputError):
            decapsulate_hybrid(b"\x00" * (SERVER_KEY_SHARE_LENGTH - 1), self.keypair)

    def test_hybrid_keypair_repr_does_not_include_private_key_material(self):
        rendered = repr(self.keypair)
        self.assertNotIn(self.keypair.mlkem_secret_key.hex(), rendered)
        self.assertNotIn(self.keypair.x25519_private_key.hex(), rendered)


if __name__ == "__main__":
    unittest.main()
