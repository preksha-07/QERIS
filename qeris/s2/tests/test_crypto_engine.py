"""
QERIS S2: Unit Tests for Cryptographic Engine (FIPS 204 ML-DSA-65, FIPS 203 ML-KEM, AEAD)
"""
import pytest
from qeris.s2.crypto_engine import (
    AuthenticationError,
    CryptoError,
    ReplayError,
    decapsulate,
    decrypt_message,
    derive_session_key,
    encapsulate,
    encrypt_message,
    generate_authority_keypair,
    generate_kem_keypair,
    sign_canonical_policy,
    verify_policy_signature,
)


def test_ml_kem_encap_decap_roundtrip():
    """Validates real FIPS 203 ML-KEM key generation, encapsulation, and decapsulation."""
    pub, priv = generate_kem_keypair("ML-KEM-768")
    ct, ss1 = encapsulate(pub, "ML-KEM-768")
    ss2 = decapsulate(ct, priv, "ML-KEM-768")

    assert ss1 == ss2
    assert len(ss1) == 32
    assert len(ct) > 0


def test_ml_kem_tampered_ciphertext_fails_secret_match():
    """One-bit modification in KEM ciphertext must not produce the same shared secret."""
    pub, priv = generate_kem_keypair("ML-KEM-768")
    ct, ss1 = encapsulate(pub, "ML-KEM-768")

    # Flip one byte
    ct_tampered = bytearray(ct)
    ct_tampered[10] ^= 0x01
    ss_tampered = decapsulate(bytes(ct_tampered), priv, "ML-KEM-768")

    assert ss_tampered != ss1


def test_hkdf_context_binding():
    """Deriving session keys with different context parameters must produce distinct keys."""
    shared_secret = b"S" * 32
    base_key = derive_session_key(
        shared_secret,
        device_id="dev_01",
        flow_id="temp_flow",
        sensitivity="LOW",
        policy_version=1,
    )
    assert len(base_key) == 32

    # Different device
    key_diff_dev = derive_session_key(
        shared_secret,
        device_id="dev_02",
        flow_id="temp_flow",
        sensitivity="LOW",
        policy_version=1,
    )
    assert key_diff_dev != base_key

    # Different flow
    key_diff_flow = derive_session_key(
        shared_secret,
        device_id="dev_01",
        flow_id="alarm_flow",
        sensitivity="LOW",
        policy_version=1,
    )
    assert key_diff_flow != base_key

    # Different sensitivity
    key_diff_sens = derive_session_key(
        shared_secret,
        device_id="dev_01",
        flow_id="temp_flow",
        sensitivity="CRITICAL",
        policy_version=1,
    )
    assert key_diff_sens != base_key

    # Different policy version
    key_diff_ver = derive_session_key(
        shared_secret,
        device_id="dev_01",
        flow_id="temp_flow",
        sensitivity="LOW",
        policy_version=2,
    )
    assert key_diff_ver != base_key


def test_aead_encrypt_decrypt_roundtrip():
    """AES-256-GCM authenticated message encryption and decryption roundtrip."""
    key = b"K" * 32
    plaintext = b"Sample Sensor Payload: 24.5 C"

    envelope = encrypt_message(
        plaintext=plaintext,
        key=key,
        device_id="dev_01",
        flow_id="temp_flow",
        sensitivity="LOW",
        policy_version=1,
        counter=1,
    )

    decrypted = decrypt_message(
        envelope_bytes=envelope,
        key=key,
        expected_device_id="dev_01",
        expected_flow_id="temp_flow",
        expected_sensitivity="LOW",
        expected_policy_version=1,
        last_seen_counter=0,
    )
    assert decrypted == plaintext


def test_aead_context_mismatch_fails_authentication():
    """Altering AAD context (device_id, flow_id, sensitivity, version) must trigger AuthenticationError."""
    key = b"K" * 32
    plaintext = b"Protected Telemetry"
    envelope = encrypt_message(
        plaintext=plaintext,
        key=key,
        device_id="dev_01",
        flow_id="temp_flow",
        sensitivity="LOW",
        policy_version=1,
        counter=1,
    )

    # Wrong device ID in expected context
    with pytest.raises(AuthenticationError):
        decrypt_message(
            envelope_bytes=envelope,
            key=key,
            expected_device_id="dev_ATTACKER",
            expected_flow_id="temp_flow",
            expected_sensitivity="LOW",
            expected_policy_version=1,
            last_seen_counter=0,
        )

    # Wrong sensitivity in expected context
    with pytest.raises(AuthenticationError):
        decrypt_message(
            envelope_bytes=envelope,
            key=key,
            expected_device_id="dev_01",
            expected_flow_id="temp_flow",
            expected_sensitivity="CRITICAL",
            expected_policy_version=1,
            last_seen_counter=0,
        )


def test_aead_ciphertext_tampering_fails():
    """Altering ciphertext or tag bytes must trigger AuthenticationError."""
    key = b"K" * 32
    plaintext = b"Sensitive Command"
    envelope = encrypt_message(
        plaintext=plaintext,
        key=key,
        device_id="dev_01",
        flow_id="cmd_flow",
        sensitivity="CRITICAL",
        policy_version=1,
        counter=1,
    )

    # Flip byte in ciphertext payload
    tampered = bytearray(envelope)
    tampered[-5] ^= 0xFF

    with pytest.raises(AuthenticationError):
        decrypt_message(
            envelope_bytes=bytes(tampered),
            key=key,
            expected_device_id="dev_01",
            expected_flow_id="cmd_flow",
            expected_sensitivity="CRITICAL",
            expected_policy_version=1,
            last_seen_counter=0,
        )


def test_counter_replay_and_out_of_order_rejected():
    """Messages with duplicate or backwards counter values must raise ReplayError."""
    key = b"K" * 32
    env1 = encrypt_message(b"msg 1", key, "dev_01", "flow_1", "LOW", 1, counter=1)
    env2 = encrypt_message(b"msg 2", key, "dev_01", "flow_1", "LOW", 1, counter=2)

    # Decrypt counter=1 (last seen was 0)
    d1 = decrypt_message(env1, key, "dev_01", "flow_1", "LOW", 1, last_seen_counter=0)
    assert d1 == b"msg 1"

    # Replay counter=1 (last seen is now 1) -> ReplayError
    with pytest.raises(ReplayError):
        decrypt_message(env1, key, "dev_01", "flow_1", "LOW", 1, last_seen_counter=1)

    # Out of order: message with counter=1 when last seen is 2 -> ReplayError
    with pytest.raises(ReplayError):
        decrypt_message(env1, key, "dev_01", "flow_1", "LOW", 1, last_seen_counter=2)
