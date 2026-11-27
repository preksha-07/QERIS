# QERIS S1 — Cryptographic Design Decisions & Architectural Status

**Document Version:** 1.0.0
**Date:** 2026-11-26
**Status:** Canonical S1 Reference
**Scope:** Cryptography and Device Implementation (`qeris/s1/`)

---

## 1. Purpose & Scope

This document records the exact architectural, parameter, and protocol decisions implemented in QERIS Step 1 (S1), explicitly delineating:
1. **Implemented and Tested** components verified by reproducible test suites.
2. **Documented but Awaiting Approval** decisions requiring mentor/team sign-off.
3. **Not Implemented** features deferred to hardware or future development stages.

This clarity prevents unverified claims regarding standards compliance, post-quantum authentication status, and hardware validation.

---

## 2. Decision Status Summary Matrix

| Decision Domain | Current Technical State | Classification | Formal Action Required |
|---|---|---|---|
| **ML-KEM Parameter Set** | ML-KEM-512 in `PQC` profile;<br>ML-KEM-768 in `HYBRID` profile | **Documented, Awaiting Unification Approval** | Formal decision to unify pure PQC to ML-KEM-768 or maintain multi-tier security levels. |
| **Device Authentication** | Challenge-bound Ed25519 signature in `device_auth.py` | **Implemented & Tested (Classical Auth Only); Awaiting DEC-1 Approval** | Formal mentor approval to accept Ed25519 as an approved variant under DEC-1. |
| **Hybrid Construction** | RFC 10024 share ordering + RFC 9958 concatenated combiner via HKDF-SHA256 | **Implemented & Tested (Application-Level Simulator)** | Formal acknowledgement that Hybrid is an application-level combiner, not TLS 1.3. |
| **Symmetric Nonce Lifecycle** | In-memory 96-bit monotonic counter, resets on process restart | **Implemented & Tested (With Operational Constraint)** | S2/S3 operational policy enforcing mandatory re-handshake on process restart. |
| **Policy Authority Signing** | Offline ML-DSA-65 envelope signer (`offline_signer.py`) | **Implemented & Tested** | Fully aligned with Master Blueprint. Runtime gateway verifies; never signs. |
| **ESP32 Hardware Calibration** | Synthetic delays only in `device_simulator.py` | **Not Implemented / Pending Hardware** | Physical bench measurements required; synthetic delays must not be cited as hardware data. |

---

## 3. Cryptographic Decision 1: ML-KEM Parameter Set Split

### 3.1 Background & Blueprint Specification
The QERIS Master Blueprint specifies **ML-KEM-768** (NIST FIPS 203, Category 3 / 192-bit classical security equivalent) as the default post-quantum key encapsulation mechanism.

### 3.2 Current Implementation State
Two distinct ML-KEM parameter sets currently coexist in S1:
1. **ML-KEM-512 (FIPS 203 Level 1 / 128-bit security):**
   - Implemented in: `qeris/s1/qeris/session_crypto.py`.
   - Used by: `DeviceProfile.PQC` in `device_simulator.py`.
   - Artifact sizes: Public key = 800 bytes; Ciphertext = 768 bytes; Shared secret = 32 bytes.
   - Rationale: Established early in S1 prototype development for minimal wire overhead in memory-constrained IoT contexts.
2. **ML-KEM-768 (FIPS 203 Level 3 / 192-bit security):**
   - Implemented in: `qeris/s1/qeris/hybrid_session_crypto.py`.
   - Used by: `DeviceProfile.HYBRID` in `device_simulator.py`.
   - Artifact sizes: Public key = 1184 bytes; Ciphertext = 1088 bytes; Shared secret = 32 bytes.
   - Rationale: Required for standard Hybrid construction alignment with modern drafts (e.g., X25519MLKEM768).

### 3.3 Strict Governance Rule
- Both parameter sets are verified and supported by `liboqs-python` (native liboqs 0.16.0).
- S1 will **not** silently overwrite or replace ML-KEM-512 in `session_crypto.py`. Existing tests and compatibility baselines depend on ML-KEM-512.
- **Pending Decision:** Awaiting team/mentor approval on whether:
  - **Option A:** Unify all PQC paths to ML-KEM-768 to strictly match the Master Blueprint.
  - **Option B:** Maintain both as explicit profiles (`PQC_LEVEL_1` / ML-KEM-512 and `PQC_LEVEL_3` / ML-KEM-768) to evaluate IoT trade-offs.

---

## 4. Cryptographic Decision 2: Device Authentication (DEC-1 Status)

### 4.1 Master Blueprint DEC-1 Options
Master Blueprint Decision Record 1 (DEC-1) defines three prospective options for IoT edge device authentication:
- **Option 1:** Pre-Shared Key (PSK) per device.
- **Option 2:** Post-Quantum Asymmetric Authentication via per-device ML-DSA-65.
- **Option 3:** Unauthenticated devices with documented risk acceptance.

### 4.2 Implemented Mechanism
- Implemented in: `qeris/s1/qeris/device_auth.py`.
- Cryptographic Primitive: **Ed25519** (RFC 8032) digital signatures.
- Flow: Freshness challenge issued by gateway (32-byte CSPRNG token), signed by device with canonical domain-separated framing:
  `b"QERIS-DEVICE-AUTH-v1\x00" || challenge || device_id || flow_id || timestamp || public_key`
- Verification: Validates cryptographic signature, challenge single-use, freshness window, and binding.

### 4.3 Cryptographic Limitation & Classification
- **Ed25519 is Classical Cryptography:** Ed25519 relies on the discrete logarithm problem over Curve25519 and is **vulnerable to Shor's algorithm on a quantum computer**.
- Ed25519 provides **no post-quantum authentication**.
- It is implemented in S1 as a robust classical asymmetric authentication mechanism to protect against classical spoofing, active MITM, and replay attacks.
- **Approval Status:** **PENDING DEC-1 FORMAL APPROVAL**. It is documented and tested, but cannot be presented as an authorized DEC-1 post-quantum design decision without formal review.

---

## 5. Cryptographic Decision 3: Hybrid Construction & Combiner Standards Alignment

### 5.1 Implemented Hybrid Scheme
- Implemented in: `qeris/s1/qeris/hybrid_session_crypto.py`.
- Profile: `DeviceProfile.HYBRID` (`X25519MLKEM768`).
- Component 1: **Classical Ephemeral X25519** (RFC 7748, 32-byte public key, 32-byte shared secret).
- Component 2: **Post-Quantum ML-KEM-768** (FIPS 203, 1184-byte public key, 1088-byte ciphertext, 32-byte shared secret).

### 5.2 Component Share & Combiner Specifications
1. **Share Ordering (RFC 10024):**
   - Client Key Share (1216 bytes): `ML-KEM-768 encapsulation key (1184 B) || X25519 public key (32 B)`.
   - Server Key Share (1120 bytes): `ML-KEM-768 ciphertext (1088 B) || X25519 public key (32 B)`.
2. **Shared Secret Combiner (RFC 9958):**
   - Concatenated PQ/T shared secret: `combined_ss = ss_mlkem (32 B) || ss_x25519 (32 B)` (Total: 64 bytes).
3. **Session Key Derivation:**
   - QERIS HKDF-SHA256 context-bound derivation:
     `K_session = HKDF-Expand(HKDF-Extract(salt=handshake_id, IKM=combined_ss), info=context, L=32)`.
   - Context is length-prefixed: `device_id, flow_id, sensitivity_tier, policy_version`.
4. **Canonical Transcript Hash:**
   - Deterministic SHA-256 hash over domain tag `b"QERIS-HYBRID-TRANSCRIPT-v1\x00"`, client share, server share, and context.

### 5.3 Standards Conformance Limitations
- **Application-Level Construction:** This is an in-process, application-level hybrid key establishment mechanism designed for simulation and evaluation.
- **Not TLS 1.3 / DTLS 1.3:** It is **not** an implementation of RFC 8446 or RFC 9147. It does not speak TLS Record Protocol, does not parse TLS extensions, and does not claim network wire interoperability with external TLS servers.
- **Combiner Approval:** The concatenated combiner `ss_mlkem || ss_x25519` follows the RFC 9958 PQ/T approach. Formal mentor acknowledgement of this application combiner is recorded as pending.

---

## 6. Symmetric Cryptography & Nonce Lifecycle

### 6.1 Primitives
- **Encryption:** AES-256-GCM (NIST SP 800-38D).
- **Key Length:** 256 bits (32 bytes).
- **Nonce Length:** 96 bits (12 bytes), formatted as a big-endian unsigned integer starting at 0.
- **Authentication Tag:** 128 bits (16 bytes).
- **Associated Data (AAD):** Structured, length-prefixed encoding of `device_id, flow_id, sensitivity_tier, policy_version`.

### 6.2 Operational Restart Constraint
- Nonce counters are strictly maintained in memory and incremented monotonically per encrypted frame.
- Replay protection rejects duplicated or out-of-order counter values at the decryptor.
- **Critical Constraint:** Nonce counters reset upon process restart or reboot. Because AES-GCM experiences catastrophic key recovery under nonce reuse, **a fresh session key MUST be negotiated via handshake upon any restart**. Keys must never persist across process boundaries.

---

## 7. Categorized Decision Registry

### Category 1: Implemented and Tested
- [x] ML-KEM-512 session key exchange (`session_crypto.py`).
- [x] Ephemeral X25519 session key exchange (`qeris_classical/session_crypto.py`).
- [x] Hybrid X25519 + ML-KEM-768 session key exchange (`hybrid_session_crypto.py`).
- [x] HKDF-SHA256 context-bound derivation with length-prefixed info (`session_crypto.py`).
- [x] AES-256-GCM authenticated message encryption with monotonic 96-bit counter (`secure_message.py`).
- [x] Canonical 5-field signed policy schema and anti-rollback verification (`policy/signed_policy.py`).
- [x] ML-DSA-65 offline policy signer CLI (`policy/offline_signer.py`).
- [x] Ed25519 challenge-bound device authentication (`device_auth.py`).
- [x] In-process local device simulator covering PQC, Classical, and Hybrid (`device_simulator.py`).
- [x] Structured JSON device event logging adhering to the 8 S4-compatible fields (`device_simulator.py`).
- [x] Fixed-vector Known Answer Tests (KATs) for HKDF-SHA256, Ed25519, and AES-256-GCM (`tests/test_kats.py`).

### Category 2: Documented but Awaiting Approval
- [ ] Formal unification decision on ML-KEM-512 vs ML-KEM-768 across pure PQC and Hybrid profiles.
- [ ] Formal DEC-1 mentor sign-off accepting classical Ed25519 device authentication as a project-approved design.
- [ ] Formal mentor review of application-level RFC 10024 / RFC 9958 Hybrid combiner.
- [ ] Acceptance of in-memory nonce lifecycle and mandatory re-handshake policy on process reboot.

### Category 3: Not Implemented / Out of Scope
- [ ] ESP32 physical hardware firmware (Xtensa C / ESP-IDF).
- [ ] Measured physical ESP32 CPU cycles, RAM heap watermarks, or execution timings.
- [ ] Physical network wire packet capture (802.15.4 / BLE / Ethernet MTU fragmentation).
- [ ] TLS 1.3 / DTLS 1.3 protocol stack integration (Record layer, alerts, socket handshakes).
- [ ] Post-quantum asymmetric device authentication (e.g., per-device ML-DSA-65).
