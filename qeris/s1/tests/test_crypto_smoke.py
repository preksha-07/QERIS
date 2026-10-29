"""
QERIS Demo 1 — Isolated Cryptographic Smoke Test (unittest)
Milestone: Demo 1 (LOW-tier Cryptographic Primitives Smoke Test)
Author: S1 (Cryptography and Device Engineer)

Scope & Viva Notes:
- Standard-library unittest suite verifying availability and behavior of
  ML-KEM-512 and ML-DSA-65 via liboqs-python.
- Tests keypair generation, encapsulation, decapsulation, and shared-secret equality.
- Tests ML-DSA-65 signing, signature verification, and tamper detection.
- Strictly isolated: does NOT implement or test gateway logic, AES-GCM,
  KDF, policy validation, or device authentication.
- Adheres to security rules: never prints or leaks private keys or shared secrets.
"""

import unittest
import oqs

# Fixed non-secret test message for signature verification and tamper testing
TEST_MESSAGE: bytes = b"QERIS-DEMO1-TEST-PAYLOAD-NON-SECRET-BASELINE"


class TestCryptoSmoke(unittest.TestCase):
    """Smoke test suite for QERIS post-quantum cryptographic primitives."""

    def test_01_ml_kem_512_enabled(self) -> None:
        """1. Confirm ML-KEM-512 is enabled using oqs.get_enabled_kem_mechanisms()."""
        target_kem = "ML-KEM-512"
        enabled_kems = oqs.get_enabled_kem_mechanisms()
        self.assertIn(
            target_kem,
            enabled_kems,
            f"Expected mechanism '{target_kem}' not found in enabled KEM mechanisms.",
        )

    def test_02_ml_kem_512_encap_decap_shared_secret_match(self) -> None:
        """2. Generate an ML-KEM-512 keypair, encapsulate to its public key,
        decapsulate the ciphertext, and assert both shared secrets match."""
        kem_name = "ML-KEM-512"
        kem = None
        try:
            kem = oqs.KeyEncapsulation(kem_name)
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            shared_secret_receiver = kem.decap_secret(ciphertext)

            self.assertEqual(
                shared_secret_sender,
                shared_secret_receiver,
                "Decapsulated shared secret does not match encapsulated shared secret.",
            )
        finally:
            if kem is not None:
                kem.free()

    def test_03_ml_dsa_65_enabled(self) -> None:
        """3. Confirm ML-DSA-65 is enabled using oqs.get_enabled_sig_mechanisms()."""
        target_sig = "ML-DSA-65"
        enabled_sigs = oqs.get_enabled_sig_mechanisms()
        self.assertIn(
            target_sig,
            enabled_sigs,
            f"Expected mechanism '{target_sig}' not found in enabled signature mechanisms.",
        )

    def test_04_ml_dsa_65_sign_and_verify_success(self) -> None:
        """4. Generate an ML-DSA-65 keypair, sign a fixed non-secret test message,
        and assert verification returns True."""
        sig_name = "ML-DSA-65"
        sig = None
        try:
            sig = oqs.Signature(sig_name)
            public_key = sig.generate_keypair()
            signature = sig.sign(TEST_MESSAGE)

            is_valid = sig.verify(TEST_MESSAGE, signature, public_key)
            self.assertTrue(
                is_valid,
                "Signature verification failed for authentic message and signature.",
            )
        finally:
            if sig is not None:
                sig.free()

    def test_05_ml_dsa_65_tampered_message_fails_verification(self) -> None:
        """5. Change one byte of the signed message and assert verification returns False."""
        sig_name = "ML-DSA-65"
        sig = None
        try:
            sig = oqs.Signature(sig_name)
            public_key = sig.generate_keypair()
            signature = sig.sign(TEST_MESSAGE)

            # Mutate the first byte of the message (single-bit flip)
            tampered_message = bytearray(TEST_MESSAGE)
            tampered_message[0] ^= 0x01

            is_valid = sig.verify(bytes(tampered_message), signature, public_key)
            self.assertFalse(
                is_valid,
                "Verification unexpectedly succeeded on a tampered message.",
            )
        finally:
            if sig is not None:
                sig.free()

    def test_06_ml_dsa_65_tampered_signature_fails_verification(self) -> None:
        """6. Change one byte of the signature and assert verification returns False."""
        sig_name = "ML-DSA-65"
        sig = None
        try:
            sig = oqs.Signature(sig_name)
            public_key = sig.generate_keypair()
            signature = sig.sign(TEST_MESSAGE)

            # Mutate the first byte of the signature (single-bit flip)
            tampered_signature = bytearray(signature)
            tampered_signature[0] ^= 0x01

            is_valid = sig.verify(TEST_MESSAGE, bytes(tampered_signature), public_key)
            self.assertFalse(
                is_valid,
                "Verification unexpectedly succeeded on a tampered signature.",
            )
        finally:
            if sig is not None:
                sig.free()


if __name__ == "__main__":
    unittest.main(verbosity=2)
