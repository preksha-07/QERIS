"""
S2 Test Configuration and Fixtures
"""
import os
import sys
import tempfile
import pytest

# Ensure workspace root and s2 are on sys.path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from qeris.s2.crypto_engine import generate_authority_keypair

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        yield td

@pytest.fixture
def authority_keys():
    priv_pem, pub_pem, pub_hex = generate_authority_keypair()
    return {
        "priv_pem": priv_pem,
        "pub_pem": pub_pem,
        "pub_hex": pub_hex,
        "authority_id": "QERIS-GATEWAY",
    }
