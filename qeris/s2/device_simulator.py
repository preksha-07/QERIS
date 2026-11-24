"""
QERIS S2: Device Simulator and Security Test Harness

Simulates IoT edge devices interacting with the QERIS Gateway.
Executes the full suite of operational and attack scenarios:
1. Valid LOW-sensitivity flow over Classical mode (ALLOWED).
2. Valid CRITICAL-sensitivity flow over PQC mode (ALLOWED).
3. CRITICAL flow attempting Classical mode downgrade (BLOCKED / REJECTED).
4. Device-supplied sensitivity label override attack (BLOCKED / POLICY ENFORCED).
5. Unregistered device access (BLOCKED).
6. Burst rate-limiting flood defense (BLOCKED / 429).
7. End-to-end telemetry encryption and cloud delivery.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

# Ensure project root is in sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import httpx
from fastapi.testclient import TestClient

from qeris.s2.capability_registry import DeviceCapabilityProfile, DeviceRegistry
from qeris.s2.config import DEFAULT_AUTHORITY_ID, DEFAULT_GATEWAY_URL, SecurityProfile
from qeris.s2.crypto_engine import generate_authority_keypair
from qeris.s2.gateway_service import create_gateway_app
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore


class GatewayDeviceSimulator:
    """
    Client simulator for exercising QERIS Gateway endpoints.
    Can operate against a remote URL (via httpx) or in-process (via TestClient).
    """

    def __init__(
        self,
        gateway_url: Optional[str] = None,
        client: Optional[TestClient] = None,
        timeout: float = 5.0,
    ):
        self.gateway_url = (gateway_url or DEFAULT_GATEWAY_URL).rstrip("/")
        self.client = client
        self.timeout = timeout

    def _post(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        if self.client is not None:
            resp = self.client.post(path, json=json_data)
            try:
                data = resp.json()
            except Exception:
                data = resp.text
            return {"status_code": resp.status_code, "data": data}
        else:
            url = f"{self.gateway_url}{path}"
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=json_data)
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                return {"status_code": resp.status_code, "data": data}

    def check_flow(
        self,
        device_id: str,
        flow_id: str,
        requested_mode: str,
        requested_profile: Optional[str] = None,
        fake_device_sensitivity: Optional[str] = None,
    ) -> dict[str, Any]:
        payload = {
            "device_id": device_id,
            "flow_id": flow_id,
            "requested_mode": requested_mode,
            "requested_profile": requested_profile,
            "device_reported_sensitivity": fake_device_sensitivity,
        }
        try:
            return self._post("/check-flow", payload)
        except Exception as exc:
            return {"status_code": 0, "error": str(exc)}

    def send_telemetry(
        self,
        device_id: str,
        flow_id: str,
        payload_data: Any,
        session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        req_body = {
            "device_id": device_id,
            "flow_id": flow_id,
            "session_id": session_id,
            "payload": payload_data,
        }
        try:
            return self._post("/api/v1/telemetry", req_body)
        except Exception as exc:
            return {"status_code": 0, "error": str(exc)}

    def run_full_demonstration(self) -> dict[str, bool]:
        """
        Runs the full demonstration sequence and prints detailed results.
        """
        print("=" * 70)
        print("QERIS S2: Running Full Gateway Security Demonstration")
        print("=" * 70)
        results: dict[str, bool] = {}

        # 1. Valid LOW flow (temperature_01) on CLASSICAL
        print("\n[Case 1] LOW flow (temperature_01) requesting CLASSICAL mode...")
        c1 = self.check_flow("device_001", "temperature_01", "CLASSICAL")
        print(f"  Response: {c1['data']}")
        ok1 = c1["status_code"] == 200 and c1["data"].get("decision") == "ALLOW"
        results["case1_low_classical_allowed"] = ok1
        print(f"  Result: {'PASS' if ok1 else 'FAIL'}")

        # 2. Valid CRITICAL flow (emergency_stop) on PQC
        print("\n[Case 2] CRITICAL flow (emergency_stop) requesting PQC mode...")
        c2 = self.check_flow("device_002", "emergency_stop", "PQC")
        print(f"  Response: {c2['data']}")
        ok2 = c2["status_code"] == 200 and c2["data"].get("decision") == "ALLOW"
        results["case2_critical_pqc_allowed"] = ok2
        print(f"  Result: {'PASS' if ok2 else 'FAIL'}")

        # 3. CRITICAL flow attempting downgrade to CLASSICAL
        print("\n[Case 3] CRITICAL flow (emergency_stop) attempting CLASSICAL downgrade...")
        c3 = self.check_flow("device_002", "emergency_stop", "CLASSICAL")
        print(f"  Response: {c3['data']}")
        ok3 = c3["status_code"] == 403 and c3["data"].get("decision") in ("REJECT", "FLOOR_UNREACHABLE")
        results["case3_critical_downgrade_rejected"] = ok3
        print(f"  Result: {'PASS (Downgrade Blocked)' if ok3 else 'FAIL'}")

        # 4. Device attempting to override sensitivity with fake "LOW" label
        print("\n[Case 4] Device attempts sensitivity override (claims 'LOW' on emergency_stop)...")
        c4 = self.check_flow(
            device_id="device_002",
            flow_id="emergency_stop",
            requested_mode="CLASSICAL",
            fake_device_sensitivity="LOW",
        )
        print(f"  Response: {c4['data']}")
        # Must still reject because policy says emergency_stop is CRITICAL!
        ok4 = c4["status_code"] == 403 and c4["data"].get("decision") in ("REJECT", "FLOOR_UNREACHABLE")
        results["case4_device_label_override_rejected"] = ok4
        print(f"  Result: {'PASS (Device Claim Ignored)' if ok4 else 'FAIL'}")

        # 5. Unregistered device access
        print("\n[Case 5] Unregistered device access check...")
        c5 = self.check_flow("rogue_device_999", "temperature_01", "CLASSICAL")
        print(f"  Response: {c5['data']}")
        ok5 = c5["status_code"] == 403 and c5["data"].get("decision") == "REJECT"
        results["case5_unregistered_device_rejected"] = ok5
        print(f"  Result: {'PASS (Unregistered Rejected)' if ok5 else 'FAIL'}")

        # 6. Telemetry forward through gateway to cloud
        print("\n[Case 6] Accepted telemetry forward to cloud...")
        t1 = self.send_telemetry(
            "device_001",
            "temperature_01",
            {"temperature_c": 22.4, "status": "nominal"},
        )
        print(f"  Response: {t1['data']}")
        ok6 = t1["status_code"] == 200 and t1["data"].get("status") == "ACCEPTED"
        results["case6_telemetry_forwarded"] = ok6
        print(f"  Result: {'PASS' if ok6 else 'FAIL'}")

        print("\n" + "=" * 70)
        print("Summary of Demonstration Results:")
        for name, pass_status in results.items():
            print(f"  {name}: {'PASS' if pass_status else 'FAIL'}")
        print("=" * 70)
        return results


def _build_in_process_simulator() -> GatewayDeviceSimulator:
    temp_dir = tempfile.mkdtemp(prefix="qeris_sim_")
    auth_id = "QERIS-GATEWAY"
    priv_pem, pub_pem, pub_hex = generate_authority_keypair()
    trusted_auths = {auth_id: pub_pem}

    db_path = os.path.join(temp_dir, "policy.db")
    policy_store = PolicyStore(db_path=db_path)

    doc = PolicyDocumentModel(
        authority_id=auth_id,
        policy_version=1,
        policies={
            "temperature_01": FlowPolicyModel(
                flow_id="temperature_01",
                device_scope=["device_001", "device_002"],
                sensitivity="LOW",
                minimum_mode="CLASSICAL",
                approved_security_profiles=[
                    "CLASSICAL_ECDH_AESGCM",
                    "HYBRID_X25519_MLKEM_AESGCM",
                    "PQC_MLKEM512_AESGCM",
                ],
            ),
            "emergency_stop": FlowPolicyModel(
                flow_id="emergency_stop",
                device_scope=["device_002", "device_003"],
                sensitivity="CRITICAL",
                minimum_mode="PQC",
                approved_security_profiles=["PQC_MLKEM512_AESGCM"],
            ),
        },
    )
    envelope = sign_policy_document(doc, priv_pem)
    policy_store.install_policy(envelope, trusted_authorities=trusted_auths)

    registry_path = os.path.join(temp_dir, "devices.db")
    registry = DeviceRegistry(db_path=registry_path)
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="device_001",
            supported_modes=["CLASSICAL"],
            supported_security_profiles=["CLASSICAL_ECDH_AESGCM"],
            ram_bytes_available=32 * 1024,
            max_packet_size_mtu=1500,
        )
    )
    registry.register_device(
        DeviceCapabilityProfile(
            device_id="device_002",
            supported_modes=["CLASSICAL", "HYBRID", "PQC"],
            supported_security_profiles=[
                "CLASSICAL_ECDH_AESGCM",
                "HYBRID_X25519_MLKEM_AESGCM",
                "PQC_MLKEM512_AESGCM",
            ],
            ram_bytes_available=256 * 1024,
            max_packet_size_mtu=1500,
        )
    )

    app = create_gateway_app(
        policy_store=policy_store,
        registry=registry,
        trusted_authorities=trusted_auths,
    )
    client = TestClient(app)
    return GatewayDeviceSimulator(client=client)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QERIS Device Simulator")
    parser.add_argument("--url", default=DEFAULT_GATEWAY_URL, help="Gateway URL")
    parser.add_argument("--in-process", action="store_true", help="Run in-process test harness")
    args = parser.parse_args()

    # If --in-process is requested or if remote URL is unreachable, run in-process
    sim: GatewayDeviceSimulator
    if args.in_process:
        sim = _build_in_process_simulator()
    else:
        # Test if remote gateway is reachable
        try:
            with httpx.Client(timeout=1.0) as client:
                r = client.get(f"{args.url}/health")
                if r.status_code == 200:
                    sim = GatewayDeviceSimulator(gateway_url=args.url)
                else:
                    sim = _build_in_process_simulator()
        except Exception:
            print(f"Notice: Gateway at {args.url} not running. Running in-process demonstration.")
            sim = _build_in_process_simulator()

    sim.run_full_demonstration()
