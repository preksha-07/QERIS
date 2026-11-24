"""
Unit Tests for Persistent Anti-Rollback Policy Store (SQLite)
"""
import os
import pytest
from qeris.s2.policy_schema import FlowPolicyModel, PolicyDocumentModel
from qeris.s2.policy_signer import sign_policy_document
from qeris.s2.policy_store import PolicyStore

def make_envelope(authority_id, version, priv_pem, flows=None):
    flow_map = flows or {
        "flow1": FlowPolicyModel(
            flow_id="flow1",
            device_scope=["*"],
            sensitivity="CRITICAL",
            minimum_mode="PQC",
            approved_security_profiles=["PQC_MLKEM512_AESGCM"],
        )
    }
    doc = PolicyDocumentModel(
        authority_id=authority_id,
        policy_version=version,
        policies=flow_map,
    )
    return sign_policy_document(doc, priv_pem)

def test_install_policy_success(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env_v1 = make_envelope(authority_keys["authority_id"], 1, authority_keys["priv_pem"])
    res = store.install_policy(env_v1, trusted)

    assert res.success is True
    assert res.status == "INSTALLED_AND_ACTIVATED"
    assert store.get_highest_version(authority_keys["authority_id"]) == 1
    assert store.get_active_version() == 1
    assert store.get_active_policy() is not None

def test_anti_rollback_rejects_lower_version(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Install version 5
    env_v5 = make_envelope(authority_keys["authority_id"], 5, authority_keys["priv_pem"])
    res5 = store.install_policy(env_v5, trusted)
    assert res5.success is True
    assert store.get_highest_version(authority_keys["authority_id"]) == 5

    # Attempt to install version 4 (Rollback attack)
    env_v4 = make_envelope(authority_keys["authority_id"], 4, authority_keys["priv_pem"])
    res4 = store.install_policy(env_v4, trusted)

    assert res4.success is False
    assert res4.status == "ROLLBACK_REJECTED"
    # Highest version must remain 5, active policy must remain version 5
    assert store.get_highest_version(authority_keys["authority_id"]) == 5
    assert store.get_active_version() == 5

def test_equal_version_idempotent_if_same_digest(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env = make_envelope(authority_keys["authority_id"], 2, authority_keys["priv_pem"])
    res1 = store.install_policy(env, trusted)
    assert res1.success is True

    # Re-install exact same envelope
    res2 = store.install_policy(env, trusted)
    assert res2.success is True
    assert res2.status == "IDEMPOTENT_ACCEPTED"
    assert store.get_highest_version(authority_keys["authority_id"]) == 2

def test_equal_version_rejected_if_content_conflicts(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Version 2 with flow1
    env_a = make_envelope(authority_keys["authority_id"], 2, authority_keys["priv_pem"])
    res_a = store.install_policy(env_a, trusted)
    assert res_a.success is True

    # Different Version 2 with flow2
    different_flows = {
        "flow2": FlowPolicyModel(
            flow_id="flow2",
            device_scope=["*"],
            sensitivity="LOW",
            minimum_mode="CLASSICAL",
            approved_security_profiles=["CLASSICAL_ECDH_AESGCM"],
        )
    }
    env_b = make_envelope(authority_keys["authority_id"], 2, authority_keys["priv_pem"], flows=different_flows)
    res_b = store.install_policy(env_b, trusted)

    assert res_b.success is False
    assert res_b.status == "CONFLICTING_SAME_VERSION"

def test_fast_forward_restriction_enforced(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env_v1 = make_envelope(authority_keys["authority_id"], 1, authority_keys["priv_pem"])
    store.install_policy(env_v1, trusted)

    # Attempt to jump from version 1 to 100 with max_version_jump=5
    env_v100 = make_envelope(authority_keys["authority_id"], 100, authority_keys["priv_pem"])
    res_jump = store.install_policy(env_v100, trusted, max_version_jump=5)

    assert res_jump.success is False
    assert res_jump.status == "FAST_FORWARD_REJECTED"
    assert store.get_highest_version(authority_keys["authority_id"]) == 1

def test_restart_persistence(temp_dir, authority_keys):
    db_path = os.path.join(temp_dir, "test_policy.db")
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Store 1 writes version 3
    store1 = PolicyStore(db_path=db_path)
    env_v3 = make_envelope(authority_keys["authority_id"], 3, authority_keys["priv_pem"])
    res = store1.install_policy(env_v3, trusted)
    assert res.success is True
    assert store1.get_highest_version(authority_keys["authority_id"]) == 3

    # Simulate Gateway restart: New PolicyStore instance opening the same SQLite file
    store2 = PolicyStore(db_path=db_path)
    assert store2.get_highest_version(authority_keys["authority_id"]) == 3
    assert store2.get_active_version() == 3
    assert store2.get_active_policy() is not None

    # Rollback must still be rejected after restart
    env_v2 = make_envelope(authority_keys["authority_id"], 2, authority_keys["priv_pem"])
    res_rb = store2.install_policy(env_v2, trusted)
    assert res_rb.success is False
    assert res_rb.status == "ROLLBACK_REJECTED"


def test_sequential_version_installation(temp_dir, authority_keys):
    """Verifies that sequential policy versions 1 -> 2 -> 3 install and advance monotonic state."""
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    for v in (1, 2, 3):
        env = make_envelope(authority_keys["authority_id"], v, authority_keys["priv_pem"])
        res = store.install_policy(env, trusted)
        assert res.success is True
        assert res.status == "INSTALLED_AND_ACTIVATED"
        assert store.get_highest_version(authority_keys["authority_id"]) == v
        assert store.get_active_version() == v


def test_store_rejects_digest_and_sig_mismatch(temp_dir, authority_keys):
    """Store level rejects envelopes with modified digest or corrupted signature."""
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env = make_envelope(authority_keys["authority_id"], 1, authority_keys["priv_pem"])
    env_dict = env.model_dump()

    # Corrupt digest
    env_bad_digest = dict(env_dict)
    env_bad_digest["policy_digest"] = "f" * 64
    res1 = store.install_policy(env_bad_digest, trusted)
    assert res1.success is False
    assert res1.status == "DIGEST_MISMATCH"

    # Corrupt signature
    env_bad_sig = dict(env_dict)
    sig_chars = list(env_bad_sig["signature"])
    sig_chars[5] = "0" if sig_chars[5] != "0" else "1"
    env_bad_sig["signature"] = "".join(sig_chars)
    res2 = store.install_policy(env_bad_sig, trusted)
    assert res2.success is False
    assert res2.status == "INVALID_SIGNATURE"


def test_store_rejects_untrusted_authority(temp_dir, authority_keys):
    """Store rejects policies signed by an authority not in the trusted map."""
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    env_rogue = make_envelope("ROGUE-AUTHORITY-99", 1, authority_keys["priv_pem"])
    res = store.install_policy(env_rogue, trusted)
    assert res.success is False
    assert res.status == "UNTRUSTED_AUTHORITY"


def test_atomicity_on_simulated_db_error(temp_dir, authority_keys, monkeypatch):
    """Verifies that an error during database commit rolls back cleanly without activating in memory."""
    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    # Install v1 successfully
    env_v1 = make_envelope(authority_keys["authority_id"], 1, authority_keys["priv_pem"])
    assert store.install_policy(env_v1, trusted).success is True

    # Simulate crash/failure by monkeypatching conn.execute during v2 insert
    orig_get_conn = store._get_connection

    class FailingConnection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            if "INSERT INTO authority_state" in sql:
                raise RuntimeError("Simulated Disk/IO Failure during commit")
            return self.conn.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    from contextlib import contextmanager

    @contextmanager
    def mock_get_conn():
        with orig_get_conn() as real_conn:
            yield FailingConnection(real_conn)

    monkeypatch.setattr(store, "_get_connection", mock_get_conn)

    env_v2 = make_envelope(authority_keys["authority_id"], 2, authority_keys["priv_pem"])
    res_fail = store.install_policy(env_v2, trusted)

    assert res_fail.success is False
    assert res_fail.status == "PERSISTENCE_FAILED"

    # Reset connection and verify active memory and DB remain on v1!
    monkeypatch.undo()
    assert store.get_active_version() == 1
    assert store.get_highest_version(authority_keys["authority_id"]) == 1


def test_concurrent_policy_update_threads(temp_dir, authority_keys):
    """Multiple threads attempting concurrent policy installations serialize without corruption."""
    import threading

    db_path = os.path.join(temp_dir, "test_policy.db")
    store = PolicyStore(db_path=db_path)
    trusted = {authority_keys["authority_id"]: authority_keys["pub_pem"]}

    results = []

    def try_install(ver):
        env = make_envelope(authority_keys["authority_id"], ver, authority_keys["priv_pem"])
        res = store.install_policy(env, trusted)
        results.append((ver, res.status))

    # Spawn 4 threads attempting to install version 1 simultaneously
    threads = [threading.Thread(target=try_install, args=(1,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one thread should be INSTALLED_AND_ACTIVATED, the others IDEMPOTENT_ACCEPTED
    statuses = [s for _, s in results]
    assert statuses.count("INSTALLED_AND_ACTIVATED") == 1
    assert statuses.count("IDEMPOTENT_ACCEPTED") == 3
    assert store.get_highest_version(authority_keys["authority_id"]) == 1

