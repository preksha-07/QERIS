"""
QERIS S2: Security Gateway Main Application Entry Point

Starts the FastAPI gateway service with pre-configured authority keys,
default registered devices, and persistent anti-rollback policy store.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import (
    DEFAULT_AUTHORITY_ID,
    DEFAULT_GATEWAY_HOST,
    DEFAULT_GATEWAY_PORT,
    SecurityProfile,
)
from qeris.s2.crypto_engine import generate_authority_keypair
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore

# Authority Key storage path for local gateway demo
_BASE_DIR = Path(__file__).resolve().parent
_AUTH_KEY_DIR = _BASE_DIR / ".authority_keys"
_AUTH_KEY_DIR.mkdir(parents=True, exist_ok=True)
_PRIV_KEY_PATH = _AUTH_KEY_DIR / "authority_priv.pem"
_PUB_KEY_PATH = _AUTH_KEY_DIR / "authority_pub.pem"

if _PRIV_KEY_PATH.exists() and _PUB_KEY_PATH.exists():
    with open(_PRIV_KEY_PATH, "rb") as f:
        _authority_priv_pem = f.read()
    with open(_PUB_KEY_PATH, "rb") as f:
        _authority_pub_pem = f.read()
else:
    _authority_priv_pem, _authority_pub_pem, _ = generate_authority_keypair()
    with open(_PRIV_KEY_PATH, "wb") as f:
        f.write(_authority_priv_pem)
    with open(_PUB_KEY_PATH, "wb") as f:
        f.write(_authority_pub_pem)

# Map trusted authority ID to its public key
_trusted_authorities = {
    DEFAULT_AUTHORITY_ID: _authority_pub_pem,
    "QERIS-GATEWAY": _authority_pub_pem,  # S3 alias compatibility
}

# Initialize Storage & Registry
_policy_store = PolicyStore()
_registry = DeviceRegistry()

# Enroll default device capability profiles if not present
_default_devices = [
    DeviceCapabilityProfile(
        device_id="device_001",
        device_class="esp32_constrained",
        supported_modes=["CLASSICAL", "HYBRID"],
        supported_security_profiles=[
            SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
            SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
        ],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=1280,
    ),
    DeviceCapabilityProfile(
        device_id="device_002",
        device_class="edge_gateway",
        supported_modes=["CLASSICAL", "HYBRID", "PQC"],
        supported_security_profiles=[
            SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
            SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
            SecurityProfile.PQC_MLKEM512_AESGCM.value,
            SecurityProfile.PQC_MLKEM768_AESGCM.value,
        ],
        ram_bytes_available=1024 * 1024,
        max_packet_size_mtu=1500,
    ),
    DeviceCapabilityProfile(
        device_id="device_003",
        device_class="esp32_constrained",
        supported_modes=["CLASSICAL"],
        supported_security_profiles=[SecurityProfile.CLASSICAL_ECDH_AESGCM.value],
        ram_bytes_available=64 * 1024,
        max_packet_size_mtu=512,
    ),
    DeviceCapabilityProfile(
        device_id="dev_esp32_constrained_01",
        device_class="esp32_constrained",
        supported_modes=["CLASSICAL", "HYBRID", "PQC"],
        supported_security_profiles=[
            SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
            SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
            SecurityProfile.PQC_MLKEM512_AESGCM.value,
        ],
        ram_bytes_available=320 * 1024,
        max_packet_size_mtu=1280,
    ),
]

for dev in _default_devices:
    if not _registry.get_device(dev.device_id):
        _registry.register_device(dev)

# Install default signed policy (Version 1) if store is empty
if _policy_store.get_active_policy() is None:
    _default_doc = PolicyDocumentModel(
        authority_id=DEFAULT_AUTHORITY_ID,
        policy_version=1,
        policies={
            "temperature_01": FlowPolicyModel(
                flow_id="temperature_01",
                device_scope=["*"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=[
                    SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
            "patient_telemetry": FlowPolicyModel(
                flow_id="patient_telemetry",
                device_scope=["*"],
                sensitivity="MEDIUM",
                minimum_mode="HYBRID",
                approved_security_profiles=[
                    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                ],
            ),
            "emergency_stop": FlowPolicyModel(
                flow_id="emergency_stop",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=[
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                    SecurityProfile.PQC_MLKEM768_AESGCM.value,
                ],
            ),
            "flow_critical_01": FlowPolicyModel(
                flow_id="flow_critical_01",
                device_scope=["*"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=[
                    SecurityProfile.PQC_MLKEM512_AESGCM.value,
                    SecurityProfile.PQC_MLKEM768_AESGCM.value,
                ],
            ),
        },
    )
    _default_envelope = sign_policy_document(_default_doc, _authority_priv_pem)
    _policy_store.install_policy(_default_envelope, _trusted_authorities)

# Create the FastAPI instance
app = create_gateway_app(
    policy_store=_policy_store,
    registry=_registry,
    trusted_authorities=_trusted_authorities,
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=DEFAULT_GATEWAY_HOST, port=DEFAULT_GATEWAY_PORT)
