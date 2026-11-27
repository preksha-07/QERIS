# QERIS S1 — Cryptographic Architecture & Technical Paper Contribution

**Document Version:** 1.0.0
**Date:** 2026-11-26
**Status:** Canonical S1 Research Contribution
**Scope:** Formal Cryptographic Architecture, Protocol Specifications, and Empirical Verification

---

## 1. Abstract & System Overview

The QERIS Step 1 (S1) subsystem provides the foundational cryptographic protocols, key establishment schemes, and message-protection mechanisms for a post-quantum and agile Internet of Things (IoT) architecture. Designed to operate across classical, post-quantum, and hybrid transitions, S1 integrates:
- NIST FIPS 203 (ML-KEM) and RFC 7748 (X25519) key agreement primitives.
- An application-level hybrid post-quantum/classical combiner based on RFC 10024 and RFC 9958.
- Cryptographic context binding via HKDF-SHA256 (RFC 5869) and canonical transcript hashing.
- Authenticated payload encryption using AES-256-GCM (NIST SP 800-38D) with monotonic anti-replay counter sequencing.
- Offline administrative governance secured by NIST FIPS 204 (ML-DSA-65) post-quantum signatures over canonical JSON schemas.
- Challenge-response device authentication utilizing RFC 8032 (Ed25519).

This document serves as the formal technical contribution for academic papers, system blueprints, and project dissertations.

---

## 2. Key Encapsulation & Hybrid Session Key Agreement

To provide cryptographic agility during the quantum transition, S1 implements three distinct key establishment mechanisms:

### 2.1 Post-Quantum Profile: ML-KEM-512
ML-KEM-512 (FIPS 203, Parameter Set Category 1) provides lattice-based IND-CCA2 security with:
- Encapsulation Key Size: $800\text{ bytes}$.
- Ciphertext Size: $768\text{ bytes}$.
- Shared Secret Size: $32\text{ bytes}$ (256 bits).
- Decapsulation Key Size: $1632\text{ bytes}$.

Key encapsulation operates non-interactively: the device publishes its ephemeral public key $pk_{\text{device}}$, the receiver encapsulates a uniform shared secret $ss_{\text{pqc}} \leftarrow \text{KEM.Encap}(pk_{\text{device}})$, transmitting ciphertext $ct_{\text{pqc}}$, and the device decapsulates $ss_{\text{pqc}} \leftarrow \text{KEM.Decap}(sk_{\text{device}}, ct_{\text{pqc}})$.

### 2.2 Classical Profile: Ephemeral X25519
For legacy baselines, S1 implements ephemeral Diffie-Hellman over Curve25519 (RFC 7748):
- Ephemeral Public Key: $32\text{ bytes}$.
- Derived Shared Secret: $32\text{ bytes}$ via scalar multiplication $ss_{\text{classical}} = X25519(sk_A, pk_B)$.

### 2.3 Hybrid Profile: X25519MLKEM768
Recognizing that classical systems must bridge to post-quantum security without abandoning battle-tested hardness assumptions, S1 implements a hybrid PQ/T construction combining ML-KEM-768 (FIPS 203 Category 3) and X25519:

1. **Share Framing (RFC 10024 Ordering):**
   - Device Key Share ($1216\text{ bytes}$): $\text{Share}_{\text{client}} = pk_{\text{MLKEM768}} (1184\text{ B}) \mathbin{\Vert} pk_{\text{X25519}} (32\text{ B})$.
   - Receiver Key Share ($1120\text{ bytes}$): $\text{Share}_{\text{server}} = ct_{\text{MLKEM768}} (1088\text{ B}) \mathbin{\Vert} pk_{\text{X25519}} (32\text{ B})$.
2. **Concatenated Secret Combiner (RFC 9958):**
   Independent shared secrets $ss_{\text{pqc}} \in \{0,1\}^{256}$ and $ss_{\text{classical}} \in \{0,1\}^{256}$ are extracted and concatenated:
   $$ss_{\text{hybrid}} = ss_{\text{pqc}} \mathbin{\Vert} ss_{\text{classical}} \quad (\text{Length: } 64\text{ bytes})$$
3. **Security Properties:**
   The hybrid secret remains secure if **either** the hardness of Module Learning with Errors (M-LWE) holds against quantum cryptanalysis **or** the elliptic-curve discrete logarithm problem holds against classical cryptanalysis.

---

## 3. Context-Bound Key Derivation & Handshake Transcript Binding

### 3.1 Two-Stage Extraction and Expansion
Raw shared secrets are never utilized directly as symmetric keys. Instead, S1 enforces context-bound derivation via HKDF-SHA256 (RFC 5869):

1. **Extract Phase:**
   $$\text{PRK} = \text{HKDF-Extract}(\text{salt} = \text{handshake\_id}, \text{IKM} = ss)$$
2. **Expand Phase:**
   $$K_{\text{session}} = \text{HKDF-Expand}(\text{PRK}, \text{info} = \text{ContextEncoding}, L = 32)$$

### 3.2 Canonical Context Encoding
To prevent cross-protocol and cross-flow substitution attacks, $\text{ContextEncoding}$ enforces strict length-prefixed domain separation:
$$\text{ContextEncoding} = \text{len}(dev) \mathbin{\Vert} dev \mathbin{\Vert} \text{len}(flow) \mathbin{\Vert} flow \mathbin{\Vert} \text{len}(tier) \mathbin{\Vert} tier \mathbin{\Vert} \text{uint64\_be}(version)$$

### 3.3 Transcript Hash & Channel Binding
A unique cryptographic token, $\text{handshake\_id} \in \{0, 1\}^{256}$, is computed across the complete transcript:
- **PQC Profile:** $\text{SHA-256}(b\text{"QERIS-TRANSCRIPT-v1\x00"} \mathbin{\Vert} pk_{\text{device}} \mathbin{\Vert} ct \mathbin{\Vert} \text{ContextEncoding})$.
- **Hybrid Profile:** $\text{SHA-256}(b\text{"QERIS-HYBRID-TRANSCRIPT-v1\x00"} \mathbin{\Vert} \text{Share}_{\text{client}} \mathbin{\Vert} \text{Share}_{\text{server}} \mathbin{\Vert} \text{ContextEncoding})$.

This value acts as both the salt in HKDF-Extract and the authoritative channel binding identifier for downstream logging and audit trails.

---

## 4. Authenticated Telemetry Encryption & Replay Resilience

### 4.1 AEAD Parameters
Application telemetry payloads are protected using AES-256-GCM (NIST SP 800-38D):
- Key: $256\text{-bit}$ context-derived $K_{\text{session}}$.
- Nonce: $96\text{-bit}$ ($12\text{ bytes}$) constructed from an unsigned big-endian strictly monotonic frame counter $c \in [0, 2^{96}-1)$.
- Tag: $128\text{-bit}$ ($16\text{ bytes}$) authentication tag.
- Additional Authenticated Data (AAD): Identical to the canonical $\text{ContextEncoding}$.

### 4.2 Replay Protection & Process Lifecycle Limits
1. **Replay Window & Out-of-Order Rejection:** The receiver tracks expected counter sequences and immediately rejects frames where $c_{\text{received}} \le c_{\text{last}}$ with `ReplayError`.
2. **Process Restart Vulnerability Mitigation:** Because counter $c$ is maintained in volatile memory, process restarts reset $c$ to 0. To eliminate catastrophic AES-GCM nonce reuse under the same session key, S1 enforces a **mandatory re-handshake policy** upon any process restart or reboot. Keys are never serialized or persisted to disk.

---

## 5. Device Authentication Architecture & Cryptographic Status

### 5.1 Challenge-Response Authentication
Device authenticity is established via asymmetric challenge-response:
1. Gateway generates a single-use 32-byte cryptographic challenge $\mathcal{C} \leftarrow \text{CSPRNG}()$.
2. Device signs a canonical, domain-separated challenge frame using its long-term private key:
   $$M_{\text{auth}} = b\text{"QERIS-DEVICE-AUTH-v1\x00"} \mathbin{\Vert} \mathcal{C} \mathbin{\Vert} device\_id \mathbin{\Vert} flow\_id \mathbin{\Vert} ts \mathbin{\Vert} pk_{\text{device}}$$
   $$\sigma = \text{Ed25519-Sign}(sk_{\text{device\_auth}}, M_{\text{auth}})$$
3. Gateway verifies signature validity, timestamp freshness window ($|\Delta t| \le 300\text{ s}$), and single-use challenge consumption.

### 5.2 Cryptographic Classification & Approval Limits
- **Classical Primitive:** Ed25519 relies on Curve25519 and the discrete logarithm problem. It is **vulnerable to quantum cryptanalysis via Shor's algorithm**.
- **Not Post-Quantum Authentication:** Ed25519 does not provide quantum-resistant authentication. It provides classical spoofing and MITM protection.
- **Formal Status:** Documented and tested in S1; pending formal mentor approval under DEC-1.

---

## 6. Canonical Policy Authority & Domain-Separated Signatures

### 6.1 Policy Schema & Domain Separation
QERIS network policies are validated against a canonical 5-field schema:
- `policy_version` ($\text{int} \ge 1$)
- `authority_id` ($\text{str}$)
- `flows` ($\text{dict[str, str]}$)
- `default_tier` ($\text{str}$)
- `min_profile` ($\text{str}$)

Policies are serialized using RFC 8785 canonical JSON rules (sorted keys, no extraneous whitespace, UTF-8) and signed with NIST FIPS 204 (ML-DSA-65):
$$\Sigma = \text{ML-DSA-65.Sign}(sk_{\text{auth}}, b\text{"QERIS-POLICY-v1\x00"} \mathbin{\Vert} \text{CanonicalJSON}(P))$$

### 6.2 Separation of Administrative Duties
Runtime gateways only possess authority public keys and perform read-only policy verification and anti-rollback validation. The authority private key is strictly isolated within the offline CLI tool (`qeris.policy.offline_signer`), preventing gateway compromise from escalating into policy forgery.

---

## 7. Known Answer Test (KAT) Methodology & Empirical Results

To guarantee mathematical correctness against international reference vectors, S1 implements automated KAT validation in `tests/test_kats.py`:

| Algorithm / Primitive | Standard / Reference | Test Vector Scope | Verification Result |
|---|---|---|---|
| **HKDF-SHA256** | RFC 5869 | Test Case 1 (Fixed IKM, salt, info, L=42) | Passed |
| **Ed25519** | RFC 8032 | Section 7.1 Test Vector 1 (Fixed seed, pk, msg, sig) | Passed |
| **AES-256-GCM** | NIST SP 800-38D | ACVP / CAVP fixed Key, IV, Plaintext, Tag, AAD | Passed |
| **ML-KEM-512** | NIST FIPS 203 | Parameter length verification; deterministic API check | Passed (API limitations documented) |
| **ML-DSA-65** | NIST FIPS 204 | Parameter length verification; deterministic API check | Passed (API limitations documented) |

---

## 8. Simulation Scope vs. Physical Hardware Boundaries

### 8.1 In-Process Simulator Capabilities
The local device simulator (`device_simulator.py`) provides end-to-end multi-peer cryptographic orchestration for:
- Seamless execution of PQC, Classical, and Hybrid exchanges.
- Configurable synthetic execution delays and timeout thresholds.
- Structured S4-compliant JSON telemetry logging without secret leakage.

### 8.2 Physical Hardware Limits
- **No Physical Measurements:** All timing figures in the simulator are synthetic software delays.
- **Hardware Calibration Deferred:** Physical execution cycle benchmarks, RAM watermarks, and real RF packet fragmentation measurements on ESP32 Xtensa silicon remain unperformed, pending physical bench hardware access.
