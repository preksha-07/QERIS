# Threat Model: Post-Quantum IoT Security Gateway

*Companion to the Project Architecture Summary. Section references (e.g. "Arch §9") point to that document.*

## 1. Purpose and Scope

This document identifies what the gateway must defend, against whom, and how each defence is verified. Every threat below maps to (a) an architectural mechanism and (b) a test or metric in the evaluation plan (Arch §10), so each design choice is justified by a specific attack.

**In scope:** device-gateway channel, gateway-cloud channel, signed-policy distribution, device registry and capability profiles, flow classification, session establishment (ML-KEM), packet protection, fragmentation/reassembly, failure recovery, and audit logging.

**Out of scope (see §11):** physical device tampering, side channels, firmware supply chain, gateway host/OS compromise, and policy-issuer key theft.

### 1.1 Baseline vs. Proposed Extensions

Several mechanisms in this document were proposed during threat-model drafting and are **not yet team decisions**. This section labels them so that all components implement the same interpretation.

- **Baseline** = in the finalized project scope and S2 handover.
- **Proposed** = introduced by this threat model; needs a team decision before any component relies on it. If a proposal is not adopted, the baseline mechanism still provides the stated protection, with the residual risk noted below.

**Baseline (finalized):** policy stored as JSON with fields `flow_id`, `sensitivity`, `minimum_mode`, `policy_version`, `signature`; lookup chain `flow_id → sensitivity → minimum_mode`; ML-DSA signed-policy verification; monotonic policy version with the highest accepted version stored persistently; replay and rollback protection for policies; device capability checking; security-floor enforcement and downgrade rejection; gateway-side enforcement (a device-provided security label is never trusted); ML-KEM session establishment; AEAD for application data; Device → Gateway → Cloud architecture; cause-classified recovery (loss/timeout, MTU/fragmentation, security failure).

**Terminology map:**

| Finalized term (S2) | Term used in this document | Relationship |
| --- | --- | --- |
| `flow_id` | flow key | Remains the policy lookup key |
| `sensitivity` | tier (Low / Medium / High / Critical) | Same concept: `sensitivity` is the field, the tier is its value |
| `minimum_mode` | mode floor (Classical / Hybrid / PQ) | Same concept: the per-flow floor the gateway never goes below |
| `policy_version` | version | Same; monotonic and persistent |
| `signature` | signature | Same; ML-DSA over the canonical policy |
| not in S2: `flow_to_tier` | classification lookup | Proposed name for the `flow_id → sensitivity` lookup |
| not in S2: `tier_to_suite` | protection profile | Proposed expansion of `sensitivity` and `minimum_mode` into suite parameters |

**Disposition of the items raised in review:**

| # | Item | Status | What this document says | If not adopted |
| --- | --- | --- | --- | --- |
| 1 | `flow_to_tier`, `tier_to_suite` | Proposed | Expanded form of `flow_id → sensitivity → minimum_mode`. Where both exist, the stricter result wins; neither may lower the S2 `minimum_mode`. | Implement `sensitivity` + `minimum_mode` only; suite parameters fixed by deployment config. Goals G1-G9 still hold through `minimum_mode`; the §7 parameter table becomes informative. |
| 2 | `expiry`, `revocation` | Proposed (optional fields) | Not required by S2. Baseline protection is the persistent monotonic `policy_version` (T11, T47). Expiry adds protection against a stale policy at the same version (T12); revocation covers withdrawing an algorithm or key (T16). | Residual risk: a stale policy is honoured until a newer version arrives; withdrawals need a new policy version. |
| 3 | `sig_alg` | Not finalized; recommend not carrying it as a trusted policy field | Pin the signature algorithm in gateway configuration. A sender-controlled algorithm field invites algorithm confusion (T45). | Pinned ML-DSA parameter set in gateway config. |
| 4 | RFC 8785 / JCS | Not finalized | Canonical encoding means the S2 definition: sorted keys, no unnecessary whitespace, UTF-8. For policies using only strings, booleans and integers this gives the same bytes as JCS, so JCS is an optional alignment, not a requirement. Every component that signs or verifies must use the same encoder (T46). | S2 definition as is. |
| 5 | Metadata-based classification vs. `flow_id` | Proposed | `flow_id` stays the policy key. The gateway may derive it from authenticated metadata (device ID, message type, operation, destination), or accept a device-supplied `flow_id` only as an identifier that must match that metadata. Neither is ever treated as a security label (T05). | Device-supplied `flow_id` validated against the registry; unknown or mismatched = reject. |
| 6 | Device-type defaults and data-category refinement (§6.8, §7) | Proposed | Optional layer above `flow_id`. A category may lower a tier only via an explicit signed allow-list entry, never below a message-type or destination floor. | Every flow listed explicitly with its own `sensitivity` and `minimum_mode`; unlisted flow = reject. |
| 7 | Per-tier suite mapping (§7 table) | Proposed | Structural pattern only; values to be set after benchmarking. | As item 1. |

## 2. System Model and Trust Boundaries

```
 [IoT Device] --TB1--> [ PQ Security Gateway ] --TB2--> [Cloud Services]
                          ^            ^
                      TB3 |            | TB4
              [Policy Issuer]     [Device Registry / Admin]
```

| Boundary | Crossing | Trust level |
| --- | --- | --- |
| TB1 | Device to gateway (also gateway to device) | Untrusted network, semi-trusted endpoint (devices can be cloned or compromised) |
| TB2 | Gateway to cloud (also cloud to gateway) | Untrusted network; cloud is authorized but not assumed uncompromised |
| TB3 | Policy issuer to gateway | Channel untrusted; authenticity comes only from the ML-DSA signature |
| TB4 | Registry/admin to gateway | Enrolment of device identities and capability profiles; trusted but audited |

**Important design consequence:** the gateway terminates sessions on both sides (Arch §3.1-3.2), so plaintext exists inside it. It is a trusted enforcement point, not an end-to-end encryption relay. Its compromise is therefore catastrophic (§11).

## 3. Assets

| ID | Asset | Primary property | Impact if lost |
| --- | --- | --- | --- |
| A1 | Session keys / KEM shared secrets | Confidentiality | All traffic on that session exposed or forgeable |
| A2 | Signed policy and tier tables (flow-to-tier, tier-to-suite) | Integrity, freshness | Silent fleet-wide security downgrade |
| A3 | Device registry and capability profiles | Integrity | Impersonation, forced downgrade, wrongful denial |
| A4 | Critical commands (actuation, emergency stop, credentials) | Integrity, freshness | Physical safety consequences |
| A5 | Telemetry / personal / operational data | Confidentiality, integrity | Privacy loss, bad decisions downstream |
| A6 | Gateway availability | Availability | Entire fleet loses cloud connectivity |
| A7 | Audit logs and metrics | Integrity | Attacks hidden; evaluation data corrupted |
| A8 | Gateway long-term private keys / issuer public-key pin | Confidentiality / integrity | Root of trust broken |

## 4. Adversary Model

The network adversary is Dolev-Yao: it can observe, drop, delay, replay, reorder, modify, and inject any message on TB1 and TB2.

| ID | Adversary | Capability |
| --- | --- | --- |
| ADV1 | On-path network attacker | Full control of traffic on TB1/TB2 |
| ADV2 | Rogue / unregistered device | No valid credentials; tries to join or spoof |
| ADV3 | Compromised registered device | Valid identity, attacker-controlled behaviour; may lie about capabilities or flow type |
| ADV4 | Compromised cloud application | Authorized channel; issues malicious or unauthorized commands |
| ADV5 | Policy forger / replayer | Can deliver policy files; holds old valid policies |
| ADV6 | Botnet / DDoS operator | High-volume, distributed traffic toward gateway |
| ADV7 | Harvest-now-decrypt-later (HNDL) | Records traffic today; has a future quantum computer |
| ADV8 | Malicious insider / misconfigurator | Can edit registry or tiers (accident or intent) |

## 5. Security Goals

Each goal ties to an enforcement rule in Arch §9.

| Goal | Statement |
| --- | --- |
| G1 | Only registered, authenticated devices obtain trusted sessions |
| G2 | Only authentic, fresh, non-revoked, non-rolled-back policy governs decisions |
| G3 | Security mode and tier are decided by gateway policy, never by the device |
| G4 | Critical flows never silently downgrade; they use an approved suite or are rejected and logged |
| G5 | Every accepted message is authentic, intact, fresh, and in-scope for its session and flow |
| G6 | Unverifiable data is discarded, even at the cost of delivery |
| G7 | Resource pressure degrades availability, never verification |
| G8 | Long-lived confidentiality for High/Critical data survives a future quantum adversary |
| G9 | Failures are logged for investigation without leaking sensitive data |

## 6. Threat Catalog

Columns: STRIDE category; mitigation; the test that demonstrates it. "Tier" is the most affected sensitivity level.

### 6.1 Traffic Ingestion and Device Interface

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T01 | Rogue device attempts a session | S | All | Registry check before any session; unregistered = no trusted session (G1) | Unauthorized-device-denied count |
| T02 | Cloned device identity reused from another location | S | High+ | Identity bound to per-device credential; anomaly alert on concurrent sessions | Clone test: two sessions, one identity |
| T03 | Malformed or oversized envelope crashes the parser | D, E | All | Strict length-checked parsing, fuzzing, reject on any parse error | Fuzz run, zero crashes |
| T04 | Metadata (flow ID, topic) modified in transit | T | All | Envelope fields authenticated (AEAD associated data), not just the body | Tamper test on header bytes |

### 6.2 Flow Classification

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T05 | Device self-declares a lower tier for a dangerous flow | S, E | Critical | Tier comes only from the signed flow-to-tier table; message content is never trusted for tier | Device claims "Low" on an e-stop flow; gateway still applies Critical |
| T06 | Topic / message-type spoofing to reach a weaker flow entry | S | High+ | Flow key is the tuple (authenticated device ID, message type, operation, destination), not the topic string alone | Spoofed-topic test |
| T07 | Unknown flow defaults to weak protection | E | All | Fail closed: unregistered flow is rejected or treated as most-restrictive | Unregistered-flow test |
| T08 | Attacker forces many flows into the Critical (costly) path | D | Critical | Tier is policy-assigned, so attackers cannot upgrade it; rate limits apply per device | Load test with mixed flows |
| T09 | Wrong tier assigned during policy authoring | T | Any | Lowering below the device-type default only via explicit signed allow-list entries, never below message-type floors (§7); rubric-based review | Policy lint check |

### 6.3 Policy and Capability Manager

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T10 | Forged or unsigned policy | S, T | All | ML-DSA verification against pinned issuer key; reject and log (G2) | Invalid-signature-rejected count |
| T11 | Replay of an old, validly signed, weaker policy (rollback) | E | All | Monotonic version number plus revocation list; stale versions rejected regardless of signature | Rollback test |
| T12 | Expired policy still honoured (or wrongly rejected because the device clock is wrong) | T, D | All | Expiry check against a trusted time source; define behaviour when time is unreliable (keep last-good policy, never default to "no policy") | Clock-skew test |
| T13 | Device lies about its capabilities to force Classical | S, E | High+ | Capability profile comes from the registry (TB4), not self-report; mismatch is logged | Lying-device downgrade test |
| T14 | Device claims more capability than it has, causing failures that tempt a fallback | D | Any | Failed handshake yields rejection or an allowed fallback only; never an ad hoc downgrade | Handshake-failure test |
| T15 | Registry or tier tables edited by insider or misconfiguration | T | Any | Registry changes are signed and audit-logged; two-person rule if feasible | Registry-change audit test |
| T16 | Algorithm sunset: signed policy keeps allowing a later-broken algorithm | I | Any | Policy has per-algorithm allow-list and revocation, updated via signed policy | Algorithm-revocation test |
| T45 | Algorithm confusion: a sender-controlled signature-algorithm field selects a weaker or wrong verifier | S, T | All | Signature algorithm pinned in gateway configuration; any algorithm field in the envelope must equal the pinned value or the policy is rejected | Wrong-algorithm envelope test |
| T46 | Signer and verifier canonicalize differently, so valid policies fail or two encodings verify as one | T, D | All | One shared canonical-encoding definition (S2: sorted keys, no whitespace, UTF-8) used by every component, with shared test vectors | Cross-component test-vector check |
| T47 | Highest accepted policy version lost on reboot or storage reset, re-enabling rollback | E | All | Persist the highest accepted version atomically; on missing or corrupt state, fail closed until an authenticated policy is loaded | Reboot-rollback test |

### 6.4 Cryptographic Session Manager

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T17 | Successful ML-KEM exchange treated as authorization | S | All | Authentication and policy check are separate, mandatory steps (Arch §7.1) | Unauthenticated-handshake test |
| T18 | Downgrade: attacker strips PQ/hybrid offer to force Classical | T | High+ | Mode chosen by policy; negotiation transcript authenticated; Critical = reject, not fall back (G4) | Downgrade-attempts-blocked count |
| T19 | Hybrid mode weakened by dropping or ignoring one component | T | High+ | Secret derived from both components via a proper KDF; either failing aborts the session | Component-strip test |
| T20 | Malformed KEM ciphertext or key triggers undefined behaviour | D, T | All | Use vetted library (liboqs); length and format checks before decapsulation | Fuzzed ciphertext test |
| T21 | Session key or nonce reuse (catastrophic for GCM-type AEAD) | I, T | All | Per-session keys; nonce derived from a strictly increasing counter; rekey before counter limit | Nonce-uniqueness test |
| T22 | Session reused across flows or tiers | E | High+ | Session bound to (device, flow, tier, policy version); mismatch forces new session (Arch §9) | Cross-flow reuse test |
| T23 | Expired or revoked session still accepted | E | Any | Expiry and revocation checked per message; session lifetime shorter for higher tiers | Expiry test |
| T24 | Renegotiation storm used to exhaust CPU | D | Any | Rate-limit handshakes per device; stateless pre-check (§8) | Handshake flood test |

### 6.5 Packet Protection and Reassembly

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T25 | Ciphertext, header, or tag modified | T | All | AEAD with header as associated data; any failure = discard (G6) | Tampered-messages-rejected count |
| T26 | Replay of a valid message or fragment | S, T | All | Per-session sequence number and bounded replay window | Replay-detected count |
| T27 | Delayed delivery of a stale Critical command | T | Critical | Freshness bound (timestamp or counter plus max age) enforced by the receiver; late commands discarded | Delayed-command test |
| T28 | Bogus fragments injected to corrupt a valid message | T | Any | Each fragment authenticated before buffering; invalid never combined with valid (Arch §8.1) | Fragment-injection test |
| T29 | Incomplete-fragment flood exhausts memory | D | Any | Bounded reassembly buffer, per-session cap, timeout cleanup | Memory stays below cap under flood |
| T30 | Large PQ keys and signatures increase fragmentation, widening attack surface | D, T | High+ | Measure fragmentation rate per mode; cap fragments per message; prefer fewer, larger frames where the link allows | Fragmentation-overhead metric |

### 6.6 Failure Recovery and Downgrade Prevention

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T31 | Induced packet loss pushes the gateway to "fail open" | T, E | Critical | Rule: unverifiable = discarded; no verification bypass for delivery (Arch §8.2) | Loss-injection test with zero unverified accepts |
| T32 | Forced retransmission loop drains resources | D | Any | Bounded retries with backoff, then controlled failure report | Retry-cap test |
| T33 | Fallback path becomes a back door | E | High+ | Fallback exists only where policy explicitly allows it for that tier; each use is logged | Fallback-audit test |
| T48 | A security failure is misclassified as loss/timeout, so retry or fallback becomes a bypass | T, E | High+ | The cause class is set by the verification result, never by timing alone; the security-failure class is terminal for that message | Tampered message is never retried as a loss |

**Cause-classified recovery (baseline).** The recovery action depends on the classified cause, so an attacker cannot trade security for delivery:

| Cause class | Examples | Allowed response | Never allowed |
| --- | --- | --- | --- |
| Loss / timeout | Missing or late packets, no acknowledgement | Bounded retry with backoff and fresh sequence numbers; report failure after the cap | Skipping verification, widening the replay window, accepting a Critical command past its freshness bound |
| MTU / fragmentation | Message exceeds path MTU; PQ keys and signatures add size | Adjust fragment size; fragment within bounded buffers; authenticate every fragment | Dropping authentication to fit, unbounded reassembly |
| Security failure | Bad signature or tag, replay, downgrade attempt, failed policy check | Discard, log, count for metrics; optionally end the session | Retrying in a weaker form, falling back to a weaker mode, treating it as loss (T48) |

### 6.7 Cloud-Side and Gateway-Level

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T34 | Compromised cloud app sends unauthorized or out-of-policy commands | E | Critical | Gateway checks sender authorization and per-command policy (Arch §4.2); commands to Critical actuators need strict auth and audit | Unauthorized-command test |
| T35 | Plaintext exposure inside the gateway (session termination point) | I | All | Minimise plaintext lifetime; zero buffers after use; host hardening listed as an assumption | Review checklist |
| T36 | Log injection or log flooding hides attacks or leaks data | R, I | Any | Structured logs; no secrets or payloads in logs; log rate limits | Log-content test |
| T37 | Harvest-now-decrypt-later on classical-only traffic | I | High+ | Tier policy requires Hybrid/PQ for High/Critical (G8); Classical only for short-lived Low data | Policy check: no High/Critical flow with Classical |

### 6.8 Device-Type Defaults and Data-Category Refinement

The tier is `lookup(device_type, data_category)`. The device type sets the default (e.g. ESP32 node = Low, refrigerator = Medium, phone = High); a registered data category may lower or raise it. Anything unmatched keeps the device-type default.

| ID | Threat | STRIDE | Tier | Mitigation | Verified by |
| --- | --- | --- | --- | --- | --- |
| T38 | Compromised device labels sensitive data as a low-risk category | S, E | High+ | Category validated against destination endpoint and registered app/service ID; mismatch falls back to the device-type default and is logged | Mislabel test: location data labelled "battery status" |
| T39 | Malicious entry added to the lowering allow-list | T | All | Allow-list is part of the ML-DSA-signed policy, with version, rollback, and revocation checks; changes audit-logged | Policy-tamper test |
| T40 | Unknown or unlabeled data gets a weak tier | E | High+ | No match never lowers the tier; default is the device-type tier ("default high, lower only by explicit allow-list") | Unknown-category test |
| T41 | Sensitive data routed through a low-tier destination | I | High+ | Gateway enforces allowed (category, destination) pairs; destination is known to the gateway, not claimed by the device | Cross-destination test |
| T42 | Device-type profile lowers a flow that has a hard floor (credential, command, emergency) | E | Critical | Message-type floors override any profile lowering; policy lint rejects such entries | Floor-override test |
| T43 | Device claims a different device type to get a lower default | S | High+ | Device type comes from the registry (TB4), bound to the device credential, never self-reported | Type-spoof test |
| T44 | One session per tier per device multiplies state and handshakes | D | Any | One reusable session per (device, tier); cap sessions per device; rate-limit new sessions | Session-cap test |

## 7. Sensitivity Tiers: How a Flow Becomes a Cipher Suite

**Step A: classify (gateway-owned, signed lookup).** The gateway extracts metadata only: authenticated device ID, message type, operation, destination. It never inspects the payload value (the tier must be known before decryption). The tuple resolves to a `flow_id`, which is looked up in the signed policy (`flow_id → sensitivity → minimum_mode`); the device never asserts its own tier (T05). In the expanded model this lookup is called flow-to-tier and the next step tier-to-suite (proposed; see §1.1).

**Message-type hierarchy (sets the default floor):**

| Order | Message type | Typical floor |
| --- | --- | --- |
| 1 | Telemetry / report | Low |
| 2 | Status / heartbeat | Low-Medium |
| 3 | Configuration update | Medium |
| 4 | Alert / event | Medium-High |
| 5 | Command / actuation | High |
| 6 | Credential / key / policy management | Critical |
| 7 | Emergency / safety command | Critical |

**Device type and data category.** The device type (taken from the registry, not self-reported, T43) sets the default tier, e.g. ESP32 node = Low, refrigerator = Medium, phone = High. Within one device type, a registered data category can refine it so that small, harmless data is not forced through the highest tier. Example for a phone: messages, health, payments, and location = High; credentials = Critical; crash logs and anonymous stats = Medium; battery and heartbeat = Low. The category is read from authenticated metadata only (destination endpoint, registered app/service ID, message type), never from the payload.

Rules: (1) default high, lower only by explicit signed allow-list entry (T38-T41); (2) unmatched or unlabeled data keeps the device-type default; (3) message-type floors (credential, command, emergency = Critical) always win (T42). Cost note: the expensive step is the ML-KEM handshake, not per-message AEAD, so one reusable session per (device, tier) keeps the overhead of fine-grained tiers small (T44); this is measured per tier in the evaluation.

The tier for each registered flow is justified offline by an impact rubric (safety, confidentiality, integrity, time-criticality, regulatory); the highest dimension drives the tier, not the average.

**Step B: map tier to protection profile (proposed; confirm after benchmarking on target hardware).**

| Tier | Mode policy | KEM | Auth | AEAD | Session lifetime | Replay window |
| --- | --- | --- | --- | --- | --- | --- |
| Low | Classical allowed | ECDH or ML-KEM-512 | Device identity | AES-128-GCM | Long | Standard |
| Medium | Hybrid preferred | Hybrid with ML-KEM-512/768 | Device credential | AES-128-GCM / ChaCha20-Poly1305 | Moderate | Standard |
| High | Hybrid or PQ required | ML-KEM-768 | Mutual authentication | AES-256-GCM | Short, scheduled rekey | Tight |
| Critical | PQ required, no fallback | ML-KEM-1024 | Mutual auth, session bound to policy version | AES-256-GCM | Shortest, frequent rekey | Strictest, enhanced audit |

ML-KEM-512/768/1024 correspond to NIST security categories 1/3/5; ML-DSA-44/65/87 to categories 2/3/5. Strength is therefore cited from NIST, while operational cost (latency, bytes, CPU, memory) is measured per tier in the evaluation.

**Step C: intersect with device capability.** Device supports the tier's suite: proceed. Device does not, tier Low/Medium: fall back only if policy explicitly permits. Device does not, tier High/Critical: reject and log (G4).

## 8. Denial of Service and DDoS

The gateway is a single chokepoint (A6), and PQ operations cost more than classical ones, so attackers get an asymmetric advantage.

| Vector | Effect | Mitigation |
| --- | --- | --- |
| Volumetric flood on TB1/TB2 | Saturates links before application logic runs | Upstream filtering/rate limiting (deployment assumption) |
| Handshake flood (ML-KEM keygen/encaps) | CPU exhaustion | Cheap checks first, PQ work last; stateless cookie-style challenge; per-source and global handshake caps |
| Policy-verification flood | ML-DSA verify cost | Version/format pre-check; rate-limit submissions |
| Fragment / half-open session flood | Memory exhaustion | Bounded buffers, timeouts, per-session caps |
| Tier-targeted flood (Critical path is costliest) | Amplified cost | Per-device quotas that scale with tier cost |

**Rule (G7):** under load the gateway rejects excess connections; it never skips signature or tag verification to save CPU. DDoS-rejection counters are tracked separately from ordinary failure recovery.

## 9. Worked Attack Scenarios

1. **Downgrade on a Critical command (T05, T13, T18).** A compromised device reports "Classical only". Policy for Critical requires PQ/Hybrid with no fallback; the gateway rejects the flow and logs the attempt.
2. **Policy rollback (T11).** An attacker replays an old signed policy that allowed a weak suite. Version check rejects it despite a valid signature.
3. **Stale emergency command (T27).** A shutdown command is held by an on-path attacker and delivered later. Freshness bound makes the receiver discard it.
4. **Compromised cloud app (T34).** It sends an actuator command it is not authorized for. The gateway's per-command policy check blocks it before encryption.
5. **Fragment flood during packet loss (T29, T31).** The attacker exploits a lossy link to push incomplete fragments. Bounded reassembly and the discard-unverifiable rule keep memory and security intact.
6. **HNDL (T37).** Recorded Low telemetry is of little value; High/Critical data was never Classical-only, so recorded traffic stays safe.

## 10. Mapping Threats to the Evaluation Plan

| Arch §10 metric | Threats exercised |
| --- | --- |
| Invalid signatures rejected | T10, T11, T12, T45, T46, T47 |
| Replay attempts detected | T11, T26, T27 |
| Tampered messages rejected | T04, T25, T28 |
| Downgrade attempts blocked | T05, T13, T18, T19, T33 |
| Unauthorized devices denied | T01, T02, T17 |
| Recovery after failures | T29, T31, T32, T48 |
| Latency, bandwidth, CPU/memory per mode and tier | T24, T30, DDoS section |

Suggested approach: build an attack-injection harness (tamper, replay, delay, drop, flood, downgrade offers) and run the same scenarios across Classical, Hybrid, and PQ modes so security gains and costs are compared under identical conditions.

## 11. Assumptions and Residual Risks

**Assumptions:** the issuer's ML-DSA private key is protected; the gateway host is not compromised; liboqs (or equivalent) is implemented correctly; initial device enrolment is performed through a trusted process; a reasonably trustworthy time source exists, or T12 behaviour is defined.

**Residual risks (declared, not solved):** gateway host or key compromise (A8), side-channel leakage in PQ implementations, physical tampering with devices, firmware/library supply chain, issuer key theft, and end-to-end confidentiality (the gateway sees plaintext by design).

## 12. Open Decisions for the Team

1. Message envelope format: which fields travel authenticated in the clear, which are encrypted.
2. Time source and freshness mechanism (counter vs timestamp) for constrained devices without an RTC.
3. Whether constrained devices can run ML-KEM locally or rely on gateway-assisted sessions (Arch §3.1), and what that does to TB1 trust.
4. Final tier-to-suite table after benchmarking on representative hardware.
5. Rollout rules for revoking algorithms and keys via signed policy.
6. Are `expiry` and `revocation` mandatory policy fields or future extensions? (Baseline: persistent monotonic version only.)
7. Is the expanded model (`flow_to_tier`, `tier_to_suite`) the agreed implementation of `flow_id → sensitivity → minimum_mode`? If yes, record the mapping in the S2 spec so every component uses the same terms.
8. Pin the signature algorithm in gateway configuration (recommended) instead of carrying `sig_alg` in the policy.
9. Canonical encoding: confirm the S2 definition (sorted keys, no whitespace, UTF-8) as the single shared encoder, and decide whether to claim RFC 8785 compatibility.
10. Flow resolution: does the gateway derive `flow_id` from authenticated metadata, or accept a device-supplied `flow_id` that is validated against it?
11. Are device-type defaults and data-category refinement in scope, or is every flow listed explicitly?