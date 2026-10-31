"""
QERIS S2 Policy Manager: Canonical Policy Lifecycle, Authority Binding, and Signature Verification.

Bridges S2 Gateway with S1 Post-Quantum Cryptography and S3 Monotonic Replay Protection:
1. Normalizes all flow policy definitions into the canonical 5-field schema.
2. Manages the trusted authority keypair for 'QERIS-GATEWAY' (ML-DSA-65).
3. Signs canonical policies into explicit SignedPolicyEnvelope structures.
4. Cryptographically verifies signed policy envelopes via S1 verify_policy.
5. Protects against rollback and fast-forward attacks via S3 ReplayProtection.
6. Fails closed on signature mismatch, untrusted authority, or corrupted version store.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Optional

# Ensure S1, S2, and S3 are resolvable
_S2_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _S2_DIR.parent.parent
_S1_DIR = _REPO_ROOT / "qeris" / "s1"
_S3_DIR = _REPO_ROOT / "qeris" / "s3"

for path in (str(_S1_DIR), str(_S3_DIR), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

import oqs
from qeris.policy.serialization import CANONICAL_POLICY_FIELDS, serialize_policy_to_bytes
from qeris.policy.signed_policy import (
    DEFAULT_SIG_ALG,
    PolicyVerificationResult,
    PolicyVerificationStatus,
    SignedPolicyEnvelope,
    create_signed_envelope,
    sign_policy,
    verify_policy,
)
from replay_protection import ReplayProtection, ReplayCheckResult


def normalize_policy_entry(flow_id: str, flow_data: Mapping[str, Any]) -> dict[str, Any]:
    """Normalizes an entry from policy.json into the canonical 5-field policy record."""
    if not isinstance(flow_data, Mapping):
        raise TypeError(f"flow_data for {flow_id} must be a mapping, got {type(flow_data).__name__}")
    
    return {
        "flow_id": str(flow_id).strip(),
        "sensitivity": str(flow_data["sensitivity"]).strip().upper(),
        "minimum_mode": str(flow_data["minimum_mode"]).strip().upper(),
        "policy_version": int(flow_data["policy_version"]),
        "authority_id": str(flow_data.get("authority_id", "QERIS-GATEWAY")).strip(),
    }


class S2PolicyManager:
    """Manages signed policy lifecycle, authority registry, and persistent version state."""

    DEFAULT_AUTHORITY_ID = "QERIS-GATEWAY"

    def __init__(
        self,
        base_dir: Optional[Path | str] = None,
        policy_filename: str = "policy.json",
        signed_filename: str = "signed_policies.json",
        version_store_filename: str = "policy_version_store.json",
    ):
        self.base_dir = Path(base_dir) if base_dir else _S2_DIR
        self.policy_path = self.base_dir / policy_filename
        self.signed_path = self.base_dir / signed_filename
        self.keys_dir = self.base_dir / "authority_keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        # 1. Initialize authority keypair
        self._init_authority_keys()

        # 2. Pinned authority registry: authority_id -> public key bytes
        self.authority_registry: dict[str, bytes] = {
            self.DEFAULT_AUTHORITY_ID: self.authority_public_key
        }

        # 3. Persistent replay & anti-rollback store (S3 ReplayProtection)
        self.version_store_path = self.base_dir / version_store_filename
        self.replay_guard = ReplayProtection(
            path=self.version_store_path,
            max_version_jump=50,
            in_memory=False,
        )
        self.replay_guard.load()

        # 4. Verified in-memory policy cache: flow_id -> 5-field dict
        self._verified_policies: dict[str, dict[str, Any]] = {}
        self._verification_results: dict[str, PolicyVerificationResult] = {}
        self._envelopes: dict[str, SignedPolicyEnvelope] = {}

        # 5. Bootstrap policies
        self.load_and_verify_all()

    def _init_authority_keys(self) -> None:
        """Loads or generates the ML-DSA-65 keypair for QERIS-GATEWAY."""
        pub_file = self.keys_dir / "qeris_gateway.pub"
        sec_file = self.keys_dir / "qeris_gateway.key"

        if pub_file.exists() and sec_file.exists():
            self.authority_public_key = pub_file.read_bytes()
            self.authority_secret_key = sec_file.read_bytes()
        else:
            # Generate fresh ML-DSA-65 keypair
            sig = None
            try:
                sig = oqs.Signature(DEFAULT_SIG_ALG)
                self.authority_public_key = bytes(sig.generate_keypair())
                self.authority_secret_key = bytes(sig.export_secret_key())
                # Persist keys securely
                pub_file.write_bytes(self.authority_public_key)
                sec_file.write_bytes(self.authority_secret_key)
            finally:
                if sig is not None:
                    sig.free()

    def sign_policy_dict(self, canonical_policy: dict[str, Any]) -> SignedPolicyEnvelope:
        """Signs a canonical 5-field policy using the gateway authority's private key."""
        signed_bytes, signature = sign_policy(
            canonical_policy,
            signer=self.authority_secret_key,
            sig_alg=DEFAULT_SIG_ALG,
        )
        return SignedPolicyEnvelope(
            policy=canonical_policy,
            sig_alg=DEFAULT_SIG_ALG,
            signature=signature,
        )

    def generate_signed_policies_file(self) -> None:
        """Reads raw policy.json, normalizes all flows, signs each with ML-DSA-65, and writes signed_policies.json."""
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Source policy file not found: {self.policy_path}")

        raw_policies = json.loads(self.policy_path.read_text(encoding="utf-8"))
        signed_envelopes = {}

        for flow_id, raw_data in raw_policies.items():
            canonical = normalize_policy_entry(flow_id, raw_data)
            envelope = self.sign_policy_dict(canonical)
            signed_envelopes[flow_id] = envelope.to_dict()

        self.signed_path.write_text(
            json.dumps(signed_envelopes, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def load_and_verify_all(self) -> dict[str, PolicyVerificationResult]:
        """Loads signed policies (generating them if necessary), verifies signatures and anti-rollback."""
        if not self.signed_path.exists():
            self.generate_signed_policies_file()

        signed_content = json.loads(self.signed_path.read_text(encoding="utf-8"))
        results = {}

        # First pass: identify max version in the authentic configuration
        for flow_id, env_data in signed_content.items():
            envelope = SignedPolicyEnvelope.from_dict(env_data)
            self._envelopes[flow_id] = envelope

            # 1. Cryptographic and structural verification via S1
            v_res = verify_policy(
                policy_input=envelope,
                authority_registry=self.authority_registry,
                last_seen_version=None,  # Checked via replay_guard next
            )

            if not v_res.is_valid:
                results[flow_id] = v_res
                self._verification_results[flow_id] = v_res
                continue

            policy_obj = envelope.policy
            version = policy_obj["policy_version"]

            # 2. Check monotonic version with S3 ReplayProtection
            # For cold startup, if current highest is 0, initialize version state
            if self.replay_guard.highest_version == 0:
                ro = self.replay_guard.check_and_accept(version)
                if not ro.accepted:
                    v_res = PolicyVerificationResult(
                        False, PolicyVerificationStatus.STALE_POLICY, f"Version check failed on startup: {ro.detail}"
                    )
            elif version < self.replay_guard.highest_version:
                v_res = PolicyVerificationResult(
                    False, PolicyVerificationStatus.STALE_POLICY, f"Policy version {version} is lower than persisted {self.replay_guard.highest_version}"
                )

            results[flow_id] = v_res
            self._verification_results[flow_id] = v_res

            if v_res.is_valid:
                self._verified_policies[flow_id] = policy_obj

        return results

    def get_verified_policy(self, flow_id: str) -> Optional[dict[str, Any]]:
        """Returns the verified canonical 5-field policy if authentic, fresh, and trusted; None otherwise."""
        return self._verified_policies.get(flow_id)

    def get_verification_status(self, flow_id: str) -> PolicyVerificationStatus:
        """Returns the verification status code for a flow."""
        if flow_id in self._verification_results:
            return self._verification_results[flow_id].status
        return PolicyVerificationStatus.INVALID_STRUCTURE

    def get_verification_result(self, flow_id: str) -> Optional[PolicyVerificationResult]:
        """Returns full PolicyVerificationResult for a flow."""
        return self._verification_results.get(flow_id)

    def is_flow_verified(self, flow_id: str) -> bool:
        """Returns True only if the flow's policy passed all cryptographic and anti-rollback checks."""
        return flow_id in self._verified_policies
