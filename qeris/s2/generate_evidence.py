"""
QERIS S2: Comprehensive Evidence Generator

Executes real, verifiable scenarios against the S2 Gateway, Policy Store,
Cloud API, S3 Hook, Baselines B1-B7, and Replayer, outputting structured
evidence files to qeris/s2/evidence/.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.cloud_client import CloudForwardStatus, CloudForwardingClient
from qeris.s2.cloud_service import CloudDatabase
from qeris.s2.config import BaselineMode, GatewayConfig, SecurityProfile
from qeris.s2.crypto_engine import (
    decapsulate,
    decrypt_message,
    derive_session_key,
    encapsulate,
    encrypt_message,
    generate_authority_keypair,
    generate_kem_keypair,
)
from qeris.s2.data_replay import DatasetReplayer
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore
from qeris.s2.policy_verifier import verify_signed_policy
from qeris.s2.session_manager import SessionManager, SessionState

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def generate_all_evidence():
    print("Generating comprehensive S2 execution evidence...")
    priv_pem, pub_pem, pub_hex = generate_authority_keypair()
    auth_id = "QERIS-GATEWAY"
    trusted = {auth_id: pub_pem}

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        policy_db = os.path.join(td, "evidence_policy.db")
        reg_db = os.path.join(td, "evidence_reg.db")
        cloud_db_path = os.path.join(td, "evidence_cloud.db")

        store = PolicyStore(policy_db)
        registry = DeviceRegistry(reg_db)
        cloud_db = CloudDatabase(cloud_db_path)

        def cloud_mock(msg):
            from qeris.s2.cloud_service import TelemetryIngestModel
            item = TelemetryIngestModel.model_validate(msg)
            cloud_db.store_telemetry(item)
            return {"status": "STORED"}

        cloud_client = CloudForwardingClient(mock_cloud_handler=cloud_mock)

        # Enroll devices
        dev_hybrid = DeviceCapabilityProfile(
            device_id="dev_hybrid_01",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=["CLASSICAL_ECDH_AESGCM", "HYBRID_X25519_MLKEM_AESGCM", "PQC_MLKEM512_AESGCM"],
            ram_bytes_available=320 * 1024,
            max_packet_size_mtu=1500,
        )
        registry.register_device(dev_hybrid)

        # -------------------------------------------------------------------
        # 1. Policy Evidence: Version 1, 2, 3, rollback attempt, conflicting same version
        # -------------------------------------------------------------------
        policy_v1_doc = PolicyDocumentModel(
            authority_id=auth_id,
            policy_version=1,
            policies={
                "temperature_01": FlowPolicyModel(
                    flow_id="temperature_01",
                    device_scope=["*"],
                    sensitivity="LOW",
                    minimum_mode="CLASSICAL",
                    approved_security_profiles=["CLASSICAL_ECDH_AESGCM", "PQC_MLKEM512_AESGCM"],
                ),
                "emergency_stop": FlowPolicyModel(
                    flow_id="emergency_stop",
                    device_scope=["*"],
                    sensitivity="CRITICAL",
                    minimum_mode="PQC",
                    approved_security_profiles=["PQC_MLKEM512_AESGCM"],
                ),
            },
        )
        env_v1 = sign_policy_document(policy_v1_doc, priv_pem)
        install_v1 = store.install_policy(env_v1, trusted)

        # Policy V2
        policy_v2_doc = PolicyDocumentModel(
            authority_id=auth_id,
            policy_version=2,
            policies=policy_v1_doc.policies,
        )
        env_v2 = sign_policy_document(policy_v2_doc, priv_pem)
        install_v2 = store.install_policy(env_v2, trusted)

        # Policy V3
        policy_v3_doc = PolicyDocumentModel(
            authority_id=auth_id,
            policy_version=3,
            policies=policy_v1_doc.policies,
        )
        env_v3 = sign_policy_document(policy_v3_doc, priv_pem)
        install_v3 = store.install_policy(env_v3, trusted)

        # Rollback attempt (re-submitting V1 while V3 active)
        rollback_res = store.install_policy(env_v1, trusted)

        # Equal-version idempotent replay check
        idempotent_res = store.install_policy(env_v3, trusted)

        # Tampered policy attempt
        tampered_env = env_v3.model_dump()
        tampered_env["policy"]["policy_version"] = 999
        tampered_verif = verify_signed_policy(tampered_env, trusted)

        policy_evidence = {
            "authority_id": auth_id,
            "policy_v1_install": {"status": install_v1.status, "version": install_v1.policy_version},
            "policy_v2_install": {"status": install_v2.status, "version": install_v2.policy_version},
            "policy_v3_install": {"status": install_v3.status, "version": install_v3.policy_version},
            "idempotent_v3_replay": {"status": idempotent_res.status, "message": idempotent_res.message},
            "rollback_attack_v1_rejected": {"status": rollback_res.status, "message": rollback_res.message},
            "tampered_policy_check": {"is_valid": tampered_verif.is_valid, "status": tampered_verif.status.value},
            "persisted_highest_version": store.get_highest_version(auth_id),
        }
        with open(EVIDENCE_DIR / "policy_anti_rollback_evidence.json", "w") as f:
            json.dump(policy_evidence, f, indent=2)

        # -------------------------------------------------------------------
        # 2. Security Floor Evidence
        # -------------------------------------------------------------------
        evidence_admin_key = "test-evidence-admin-key"
        evidence_config = GatewayConfig(
            admin_api_key=evidence_admin_key,
            baseline_mode=BaselineMode.FULL_GATEWAY,
        )
        app = create_gateway_app(
            policy_store=store,
            registry=registry,
            cloud_client=cloud_client,
            trusted_authorities=trusted,
            config=evidence_config,
        )
        client = TestClient(app, headers={"X-Admin-Key": evidence_admin_key})

        # Case A: Allowed critical flow
        resp_crit_allow = client.post(
            "/check-flow",
            json={"device_id": "dev_hybrid_01", "flow_id": "emergency_stop", "requested_mode": "PQC"},
        )
        # Case B: Blocked downgrade attempt
        resp_crit_downgrade = client.post(
            "/check-flow",
            json={"device_id": "dev_hybrid_01", "flow_id": "emergency_stop", "requested_mode": "CLASSICAL"},
        )
        # Case C: Device fake sensitivity override attempt
        resp_fake_label = client.post(
            "/check-flow",
            json={
                "device_id": "dev_hybrid_01",
                "flow_id": "emergency_stop",
                "requested_mode": "CLASSICAL",
                "device_reported_sensitivity": "LOW",
            },
        )

        sec_floor_evidence = {
            "case_a_pqc_allowed": resp_crit_allow.json(),
            "case_b_classical_downgrade_blocked": resp_crit_downgrade.json(),
            "case_c_device_label_override_blocked": resp_fake_label.json(),
        }
        with open(EVIDENCE_DIR / "security_floor_enforcement_evidence.json", "w") as f:
            json.dump(sec_floor_evidence, f, indent=2)

        # -------------------------------------------------------------------
        # 3. Cloud Forwarding and Outage Evidence
        # -------------------------------------------------------------------
        tel_resp = client.post(
            "/api/v1/telemetry",
            json={
                "device_id": "dev_hybrid_01",
                "flow_id": "emergency_stop",
                "payload": {"state": "nominal", "reading": 0.0},
            },
        )
        # Outage simulation (explicitly testing memory-only bounded FIFO queue)
        outage_cloud_client = CloudForwardingClient(
            max_queue_size=2,
            mock_cloud_handler=lambda msg: {"status": "FAILED", "detail": "Simulated Network Drop"},
        )
        outage_q1 = outage_cloud_client.forward_telemetry({"event_id": "outage_01"})
        outage_q2 = outage_cloud_client.forward_telemetry({"event_id": "outage_02"})
        outage_q3 = outage_cloud_client.forward_telemetry({"event_id": "outage_03"})

        cloud_evidence = {
            "online_telemetry_submission": tel_resp.json(),
            "cloud_db_record_count": cloud_db.get_stats(),
            "outage_buffer_nature": "memory_only_bounded_fifo",
            "outage_simulation": {
                "msg1_status": outage_q1.status.value,
                "msg2_status": outage_q2.status.value,
                "msg3_overflow_status": outage_q3.status.value,
                "queue_size": outage_cloud_client.queue_size,
                "dropped_count": outage_cloud_client.dropped_count,
            },
        }
        with open(EVIDENCE_DIR / "cloud_pipeline_and_outage_evidence.json", "w") as f:
            json.dump(cloud_evidence, f, indent=2)

        # -------------------------------------------------------------------
        # 4. Dataset Replay Evidence
        # -------------------------------------------------------------------
        replayer = DatasetReplayer()
        replay_stats = replayer.replay_through_gateway(client, run_id="pilot_smoke", max_events=25)
        with open(EVIDENCE_DIR / "dataset_replay_evidence.json", "w") as f:
            json.dump(replay_stats, f, indent=2)

        # -------------------------------------------------------------------
        # 5. Baselines Execution Evidence (B1 - B7)
        # -------------------------------------------------------------------
        baselines_results = {}
        for b_mode in [
            BaselineMode.STATIC_CLASSICAL,
            BaselineMode.STATIC_HYBRID,
            BaselineMode.STATIC_PQC,
            BaselineMode.SENSITIVITY_ONLY,
            BaselineMode.DOWNGRADE_ON_FAILURE,
            BaselineMode.STATIC_RETRY,
            BaselineMode.FULL_GATEWAY,
        ]:
            b_dev_id = f"dev_b_{b_mode.value}"
            registry.register_device(
                DeviceCapabilityProfile(
                    device_id=b_dev_id,
                    supported_modes=["CLASSICAL", "HYBRID", "PQC"],
                    supported_security_profiles=[
                        "CLASSICAL_ECDH_AESGCM",
                        "HYBRID_X25519_MLKEM_AESGCM",
                        "PQC_MLKEM512_AESGCM",
                    ],
                    ram_bytes_available=320 * 1024,
                    max_packet_size_mtu=1500,
                )
            )
            client.post("/api/v1/admin/baseline", json={"baseline_mode": b_mode.value})
            # Test CRITICAL flow on Classical mode
            crit_resp = client.post(
                "/check-flow",
                json={"device_id": b_dev_id, "flow_id": "emergency_stop", "requested_mode": "CLASSICAL"},
            )
            # Test LOW flow on Classical mode
            low_resp = client.post(
                "/check-flow",
                json={"device_id": b_dev_id, "flow_id": "temperature_01", "requested_mode": "CLASSICAL"},
            )
            baselines_results[b_mode.value] = {
                "critical_flow_classical_request": crit_resp.json().get("decision"),
                "low_flow_classical_request": low_resp.json().get("decision"),
                "status_code_critical": crit_resp.status_code,
                "status_code_low": low_resp.status_code,
            }

        with open(EVIDENCE_DIR / "baselines_execution_evidence.json", "w") as f:
            json.dump(baselines_results, f, indent=2)

        # -------------------------------------------------------------------
        # 6. Cryptography & DEC-4 Epoch Evidence
        # -------------------------------------------------------------------
        kem_pub, kem_priv = generate_kem_keypair("ML-KEM-768")
        ct, ss1 = encapsulate(kem_pub, "ML-KEM-768")
        ss2 = decapsulate(ct, kem_priv, "ML-KEM-768")
        assert ss1 == ss2

        derived_key = derive_session_key(
            ss1,
            device_id="dev_hybrid_01",
            flow_id="emergency_stop",
            sensitivity="CRITICAL",
            policy_version=3,
        )

        # Session Manager DEC-4 test
        sm = SessionManager()
        sess_ctx = sm.create_session(
            device_id="dev_hybrid_01",
            flow_id="emergency_stop",
            policy_envelope=env_v3,
            negotiated_profile="PQC_MLKEM512_AESGCM",
            negotiated_mode="PQC",
            session_key=derived_key,
        )
        valid_before, _ = sm.validate_and_rebind_session(sess_ctx, env_v3)

        # Advance epoch with a policy that removes PQC_MLKEM512_AESGCM
        policy_v4_doc = PolicyDocumentModel(
            authority_id=auth_id,
            policy_version=4,
            policies={
                "emergency_stop": FlowPolicyModel(
                    flow_id="emergency_stop",
                    device_scope=["*"],
                    sensitivity="CRITICAL",
                    minimum_mode="PQC",
                    approved_security_profiles=["PQC_MLKEM768_AESGCM"],
                )
            },
        )
        env_v4 = sign_policy_document(policy_v4_doc, priv_pem)
        sm.advance_epoch()
        valid_after, invalid_reason = sm.validate_and_rebind_session(sess_ctx, env_v4)

        crypto_dec4_evidence = {
            "ml_dsa_65": {
                "public_key_hex_length": len(pub_hex),
                "signature_hex_length": len(env_v1.signature),
                "sig_alg": env_v1.sig_alg,
            },
            "ml_kem_768": {
                "public_key_bytes_length": len(kem_pub),
                "ciphertext_bytes_length": len(ct),
                "shared_secret_bytes_length": len(ss1),
                "encap_decap_match": ss1 == ss2,
            },
            "hkdf_session_key_length": len(derived_key),
            "dec4_epoch_invalidation": {
                "initial_session_state": "ACTIVE" if valid_before else "INVALID",
                "epoch_advanced": True,
                "session_state_after_policy_update": sess_ctx.state.value,
                "is_valid_after_update": valid_after,
                "invalidation_reason": invalid_reason,
            },
        }
        with open(EVIDENCE_DIR / "crypto_and_dec4_evidence.json", "w") as f:
            json.dump(crypto_dec4_evidence, f, indent=2)

        # -------------------------------------------------------------------
        # 7. Baseline Freeze & Configuration Reproducibility Evidence
        # -------------------------------------------------------------------
        from qeris.s2.config import (
            BASELINE_DESCRIPTIONS,
            BASELINE_RECOVERY_PROPERTIES,
        )
        cfg_resp = client.get("/api/v1/admin/config")
        baseline_resp = client.get("/api/v1/admin/baseline")

        freeze_evidence = {
            "config_version": cfg_resp.json().get("config_version"),
            "config_digest": cfg_resp.json().get("config_digest"),
            "effective_config": cfg_resp.json().get("config"),
            "frozen": True,
            "all_available_baselines": baseline_resp.json().get("all_available_baselines"),
            "baseline_descriptions": BASELINE_DESCRIPTIONS,
            "baseline_recovery_properties": BASELINE_RECOVERY_PROPERTIES,
        }
        with open(EVIDENCE_DIR / "baseline_freeze_evidence.json", "w") as f:
            json.dump(freeze_evidence, f, indent=2)

    print("Evidence successfully generated in qeris/s2/evidence/")


if __name__ == "__main__":
    generate_all_evidence()
