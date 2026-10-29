import unittest

from cryptography.exceptions import InvalidTag

from qeris.secure_message import (
    AuthenticationError,
    MessageContext,
    MessageCryptoError,
    MessageDecryptor,
    MessageEncryptor,
    ReplayError,
    MAX_ENVELOPE_SIZE,
)


class TestSecureMessage(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.context = MessageContext(
            device_id="device-01",
            flow_id="temperature",
            sensitivity_tier="LOW",
            policy_version=7,
        )

    def test_round_trip_and_counter(self):
        sender = MessageEncryptor(self.key, self.context)
        receiver = MessageDecryptor(self.key, self.context)
        first = sender.encrypt(b"hello")
        second = sender.encrypt(b"world")
        self.assertEqual(receiver.decrypt(first), b"hello")
        self.assertEqual(receiver.decrypt(second), b"world")
        self.assertEqual(receiver.last_counter, 1)

    def test_header_and_ciphertext_tampering_fail(self):
        sender = MessageEncryptor(self.key, self.context)
        envelope = sender.encrypt(b"payload")
        receiver = MessageDecryptor(self.key, self.context)

        changed_ciphertext = bytearray(envelope)
        changed_ciphertext[-1] ^= 1
        with self.assertRaises(AuthenticationError):
            receiver.decrypt(bytes(changed_ciphertext))
        self.assertEqual(receiver.last_counter, -1)

        changed_header = bytearray(envelope)
        changed_header[5] ^= 1  # modify nonce/counter bytes
        with self.assertRaises(AuthenticationError):
            receiver.decrypt(bytes(changed_header))
        self.assertEqual(receiver.last_counter, -1)

    def test_wrong_context_fails_authentication(self):
        sender = MessageEncryptor(self.key, self.context)
        envelope = sender.encrypt(b"payload")
        wrong_context = MessageContext("device-02", "temperature", "LOW", 7)
        receiver = MessageDecryptor(self.key, wrong_context)
        with self.assertRaises(AuthenticationError):
            receiver.decrypt(envelope)

    def test_each_context_field_is_bound(self):
        variants = [
            MessageContext("device-02", "temperature", "LOW", 7),
            MessageContext("device-01", "humidity", "LOW", 7),
            MessageContext("device-01", "temperature", "HIGH", 7),
            MessageContext("device-01", "temperature", "LOW", 8),
        ]
        sender = MessageEncryptor(self.key, self.context)
        envelope = sender.encrypt(b"payload")
        for context in variants:
            with self.subTest(context=context):
                receiver = MessageDecryptor(self.key, context)
                with self.assertRaises(AuthenticationError):
                    receiver.decrypt(envelope)

    def test_replay_rejected(self):
        sender = MessageEncryptor(self.key, self.context)
        receiver = MessageDecryptor(self.key, self.context)
        envelope = sender.encrypt(b"once")
        self.assertEqual(receiver.decrypt(envelope), b"once")
        with self.assertRaises(ReplayError):
            receiver.decrypt(envelope)

    def test_out_of_order_rejected(self):
        sender = MessageEncryptor(self.key, self.context)
        first = sender.encrypt(b"first")
        second = sender.encrypt(b"second")
        receiver = MessageDecryptor(self.key, self.context)
        self.assertEqual(receiver.decrypt(second), b"second")
        with self.assertRaises(ReplayError):
            receiver.decrypt(first)

    def test_malformed_envelopes_rejected(self):
        receiver = MessageDecryptor(self.key, self.context)
        for envelope in (b"", b"QMSG", b"NOPE" + b"\x01" + b"\x00" * 12 + b"x" * 16):
            with self.subTest(envelope=envelope):
                with self.assertRaises(MessageCryptoError):
                    receiver.decrypt(envelope)

    def test_oversized_envelope_rejected_before_decryption(self):
        receiver = MessageDecryptor(self.key, self.context)
        oversized = b"X" * (MAX_ENVELOPE_SIZE + 1)
        with self.assertRaisesRegex(MessageCryptoError, "maximum supported size"):
            receiver.decrypt(oversized)
        self.assertEqual(receiver.last_counter, -1)

    def test_invalid_key_and_context_rejected(self):
        with self.assertRaises(MessageCryptoError):
            MessageEncryptor(b"short", self.context)
        with self.assertRaises(MessageCryptoError):
            MessageDecryptor(self.key, "not a context")
        with self.assertRaises(MessageCryptoError):
            MessageContext("", "flow", "LOW", 1).encode()
        with self.assertRaises(MessageCryptoError):
            MessageContext("device", "flow", "LOW", True).encode()

    def test_failed_authentication_does_not_consume_counter(self):
        sender = MessageEncryptor(self.key, self.context)
        envelope = sender.encrypt(b"payload")
        receiver = MessageDecryptor(self.key, self.context)
        bad = envelope[:-1] + bytes([envelope[-1] ^ 1])
        with self.assertRaises(AuthenticationError):
            receiver.decrypt(bad)
        self.assertEqual(receiver.decrypt(envelope), b"payload")


if __name__ == "__main__":
    unittest.main()
