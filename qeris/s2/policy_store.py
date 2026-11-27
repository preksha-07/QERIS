"""
QERIS S2: Persistent Anti-Rollback Policy Version Store

Implements atomic, restart-persistent policy version tracking backed by SQLite.
Guarantees anti-rollback protection:
1. In-memory policy activation happens strictly AFTER persistent database commit.
2. If process crashes during update, uncommitted policies are rolled back automatically.
3. Monotonic version ordering is enforced: versions <= highest accepted are rejected.
4. Survives gateway restart without resetting the anti-rollback state.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from qeris.s2.canonical_json import canonical_encode
from qeris.s2.config import DEFAULT_POLICY_DB_PATH
from qeris.s2.policy_schema import SignedPolicyEnvelopeModel
from qeris.s2.policy_verifier import (
    PolicyVerificationResult,
    PolicyVerificationStatus,
)
from qeris.s2.policy_bridge import verify_unified_policy as verify_signed_policy


@dataclass
class PolicyInstallResult:
    success: bool
    status: str
    message: str
    authority_id: Optional[str] = None
    policy_version: Optional[int] = None
    policy_digest: Optional[str] = None
    envelope: Optional[SignedPolicyEnvelopeModel] = None


class PolicyStore:
    """
    Transactional SQLite-backed storage for policy versions and active signed policies.
    """

    def __init__(self, db_path: str = DEFAULT_POLICY_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._active_policy: Optional[SignedPolicyEnvelopeModel] = None
        self._init_db()
        self._load_active_policy()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS authority_state (
                    authority_id TEXT PRIMARY KEY,
                    highest_version INTEGER NOT NULL,
                    active_digest TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    authority_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    digest TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    sig_alg TEXT NOT NULL,
                    installed_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_policy_history_auth_ver
                ON policy_history(authority_id, version)
            """)

    def _load_active_policy(self) -> None:
        """Loads the newest accepted policy from database into memory upon startup."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT canonical_json, signature, sig_alg, digest
                FROM policy_history
                ORDER BY version DESC, id DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                policy_dict = json.loads(row["canonical_json"])
                self._active_policy = SignedPolicyEnvelopeModel(
                    policy=policy_dict,
                    policy_digest=row["digest"],
                    sig_alg=row["sig_alg"],
                    signature=row["signature"],
                )

    def get_highest_version(self, authority_id: str) -> int:
        """Returns the highest accepted policy version for the given authority, or 0 if none."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT highest_version FROM authority_state WHERE authority_id = ?",
                (authority_id,),
            )
            row = cursor.fetchone()
            return int(row["highest_version"]) if row else 0

    def get_active_policy(self) -> Optional[SignedPolicyEnvelopeModel]:
        """Returns the currently active, verified policy envelope."""
        return self._active_policy

    def get_active_digest(self) -> Optional[str]:
        return self._active_policy.policy_digest if self._active_policy else None

    def get_active_version(self) -> int:
        return self._active_policy.policy.policy_version if self._active_policy else 0

    def install_policy(
        self,
        envelope_data: Union[dict[str, Any], SignedPolicyEnvelopeModel],
        trusted_authorities: Mapping[str, Any],
        max_version_jump: Optional[int] = None,
    ) -> PolicyInstallResult:
        """
        Safely installs a signed policy into persistent storage and memory.

        Order of Operations:
        1. Parse and validate structure.
        2. Authenticate: Verify ML-DSA-65 signature and digest using trusted authority key.
        3. Check Anti-Rollback against persisted SQLite highest version.
        4. Validate version progression (anti-fast-forward if configured).
        5. Atomically commit new version and policy into SQLite.
        6. Activate in memory strictly after successful commit.
        """
        with self._lock:
            # 1 & 2: Cryptographic and structural verification
            verif_res = verify_signed_policy(envelope_data, trusted_authorities)
            if not verif_res.is_valid or verif_res.envelope is None:
                return PolicyInstallResult(
                    success=False,
                    status=verif_res.status.value,
                    message=verif_res.message,
                )

            envelope = verif_res.envelope
            authority_id = envelope.policy.authority_id
            incoming_version = envelope.policy.policy_version
            incoming_digest = envelope.policy_digest

            with self._get_connection() as conn:
                try:
                    # Transactional anti-rollback verification
                    conn.execute("BEGIN IMMEDIATE")

                    cursor = conn.execute(
                        "SELECT highest_version, active_digest FROM authority_state WHERE authority_id = ?",
                        (authority_id,),
                    )
                    row = cursor.fetchone()
                    highest_version = int(row["highest_version"]) if row else 0
                    current_digest = str(row["active_digest"]) if row else ""

                    # Check Anti-Rollback
                    if incoming_version < highest_version:
                        conn.execute("ROLLBACK")
                        return PolicyInstallResult(
                            success=False,
                            status="ROLLBACK_REJECTED",
                            message=f"Policy version {incoming_version} is lower than persisted highest version {highest_version} (rollback attack detected)",
                            authority_id=authority_id,
                            policy_version=incoming_version,
                            policy_digest=incoming_digest,
                        )

                    if incoming_version == highest_version:
                        # Idempotent re-acceptance only if digest matches perfectly
                        if incoming_digest == current_digest:
                            conn.execute("ROLLBACK")
                            return PolicyInstallResult(
                                success=True,
                                status="IDEMPOTENT_ACCEPTED",
                                message=f"Policy version {incoming_version} matches active version with identical digest (idempotent re-acceptance)",
                                authority_id=authority_id,
                                policy_version=incoming_version,
                                policy_digest=incoming_digest,
                                envelope=envelope,
                            )
                        else:
                            conn.execute("ROLLBACK")
                            return PolicyInstallResult(
                                success=False,
                                status="CONFLICTING_SAME_VERSION",
                                message=f"Policy version {incoming_version} equals active version but content digest differs (conflicting same-version rejected)",
                                authority_id=authority_id,
                                policy_version=incoming_version,
                                policy_digest=incoming_digest,
                            )

                    # Optional fast-forward restriction check
                    if max_version_jump is not None and highest_version > 0:
                        if (incoming_version - highest_version) > max_version_jump:
                            conn.execute("ROLLBACK")
                            return PolicyInstallResult(
                                success=False,
                                status="FAST_FORWARD_REJECTED",
                                message=f"Version jump from {highest_version} to {incoming_version} exceeds maximum allowed step {max_version_jump}",
                                authority_id=authority_id,
                                policy_version=incoming_version,
                                policy_digest=incoming_digest,
                            )

                    # 5: Atomically persist to database
                    canonical_json_str = canonical_encode(envelope.policy.canonical_dict()).decode("utf-8")
                    now = time.time()

                    conn.execute(
                        """
                        INSERT INTO policy_history (authority_id, version, digest, canonical_json, signature, sig_alg, installed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (authority_id, incoming_version, incoming_digest, canonical_json_str, envelope.signature, envelope.sig_alg, now),
                    )

                    conn.execute(
                        """
                        INSERT INTO authority_state (authority_id, highest_version, active_digest, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(authority_id) DO UPDATE SET
                            highest_version = excluded.highest_version,
                            active_digest = excluded.active_digest,
                            updated_at = excluded.updated_at
                        """,
                        (authority_id, incoming_version, incoming_digest, now),
                    )

                    conn.execute("COMMIT")

                    # 6: Activate in memory ONLY after successful commit
                    self._active_policy = envelope

                    return PolicyInstallResult(
                        success=True,
                        status="INSTALLED_AND_ACTIVATED",
                        message=f"Policy version {incoming_version} successfully persisted and activated",
                        authority_id=authority_id,
                        policy_version=incoming_version,
                        policy_digest=incoming_digest,
                        envelope=envelope,
                    )

                except Exception as exc:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    return PolicyInstallResult(
                        success=False,
                        status="PERSISTENCE_FAILED",
                        message=f"Database transaction failed: {exc}",
                        authority_id=authority_id,
                        policy_version=incoming_version,
                        policy_digest=incoming_digest,
                    )

    def get_history(self, authority_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            if authority_id:
                cursor = conn.execute(
                    "SELECT version, digest, sig_alg, installed_at FROM policy_history WHERE authority_id = ? ORDER BY version DESC",
                    (authority_id,),
                )
            else:
                cursor = conn.execute(
                    "SELECT authority_id, version, digest, sig_alg, installed_at FROM policy_history ORDER BY version DESC"
                )
            return [dict(row) for row in cursor.fetchall()]
