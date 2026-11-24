"""
Unit Tests for Canonical JSON and Policy Digest (RFC 8785)
"""
import pytest
from qeris.s2.canonical_json import CanonicalEncodingError, canonical_encode, compute_policy_digest

def test_canonical_encode_key_sorting():
    d1 = {"b": 2, "a": 1, "c": 3}
    d2 = {"a": 1, "c": 3, "b": 2}
    enc1 = canonical_encode(d1)
    enc2 = canonical_encode(d2)
    assert enc1 == enc2
    assert enc1 == b'{"a":1,"b":2,"c":3}'

def test_canonical_encode_nested_sorting():
    d1 = {"outer": {"z": 10, "m": 5}, "alpha": [3, 2, 1]}
    d2 = {"alpha": [3, 2, 1], "outer": {"m": 5, "z": 10}}
    assert canonical_encode(d1) == canonical_encode(d2)
    assert canonical_encode(d1) == b'{"alpha":[3,2,1],"outer":{"m":5,"z":10}}'

def test_canonical_encode_no_whitespace():
    d = {"key": "value with spaces", "num": 42}
    enc = canonical_encode(d)
    assert b": " not in enc
    assert b", " not in enc

def test_canonical_encode_rejects_nan_and_inf():
    with pytest.raises(CanonicalEncodingError):
        canonical_encode({"val": float("nan")})
    with pytest.raises(CanonicalEncodingError):
        canonical_encode({"val": float("inf")})

def test_canonical_encode_rejects_non_string_keys():
    with pytest.raises(CanonicalEncodingError):
        canonical_encode({1: "integer key"})

def test_compute_policy_digest_deterministic():
    d1 = {"authority_id": "AUTH1", "policy_version": 1}
    d2 = {"policy_version": 1, "authority_id": "AUTH1"}
    h1 = compute_policy_digest(d1)
    h2 = compute_policy_digest(d2)
    assert h1 == h2
    assert len(h1) == 64

def test_compute_policy_digest_changes_on_one_byte_alteration():
    d1 = {"authority_id": "AUTH1", "policy_version": 1}
    d2 = {"authority_id": "AUTH1", "policy_version": 2}
    h1 = compute_policy_digest(d1)
    h2 = compute_policy_digest(d2)
    assert h1 != h2

def test_canonical_encode_unicode_raw_utf8():
    """RFC 8785 requires UTF-8 characters to be unescaped without \\uXXXX notation."""
    d = {"city": "São Paulo", "greek": "λ", "symbol": "µs"}
    enc = canonical_encode(d)
    assert b"\\u" not in enc
    assert "São Paulo".encode("utf-8") in enc

def test_canonical_encode_empty_structures():
    """Empty objects and arrays serialize compactly."""
    assert canonical_encode({}) == b"{}"
    assert canonical_encode([]) == b"[]"
    assert canonical_encode({"arr": [], "obj": {}}) == b'{"arr":[],"obj":{}}'

def test_canonical_encode_integers_and_booleans():
    """Integers, booleans, and null values encode per RFC 8785."""
    d = {"active": True, "archived": False, "count": -42, "optional": None, "zero": 0}
    enc = canonical_encode(d)
    assert enc == b'{"active":true,"archived":false,"count":-42,"optional":null,"zero":0}'

def test_compute_policy_digest_domain_separation():
    """Verifies domain separation prefix QERIS-POLICY-v1: is included in raw digest calculation."""
    import hashlib
    d = {"authority_id": "AUTH-TEST", "policy_version": 1}
    expected_canonical = canonical_encode(d)
    expected_hash = hashlib.sha256(b"QERIS-POLICY-v1:" + expected_canonical).hexdigest()
    actual_hash = compute_policy_digest(d)
    assert actual_hash == expected_hash

