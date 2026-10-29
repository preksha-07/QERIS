# S2 - Gateway, Cloud and Integration Engineer (48 hours)

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway
**Contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes
**Teammates:** S1 (crypto/device), S3 (state machine/recovery), S4 (data science)

## 1. Your mission
Build the platform everything else runs on: the gateway, policy handling, device registry, cloud API and the integrated system. You also own the baselines the research compares against.

## 2. Responsibilities
**Primary:** architecture and interface spec, gateway service, cloud API/DB, policy schema, sensitivity classification, capability registry, readiness rules, persistent policy-version storage, gateway audit logging and rate limiting, baselines, final integration and Docker, demo.
**Secondary:** gateway/cloud paper sections and diagrams, viva prep.
**Backup for:** state machine and recovery controller (S3), KEM handshake and ESP32 integration (S1).

## 3. Tasks

| ID | Task | Hours | Weeks | Depends on | Deliverable |
|----|------|-------|-------|------------|-------------|
| T2 | Architecture and interface spec (message formats, key roles, API contracts) | 3 | 1-2 | T1 | Architecture doc |
| T11 | Policy schema: flow_id, sensitivity, minimum_mode, policy_version, signature; canonical encoding | 3 | 2 | T2 | Schema document |
| T15 | Persistent highest-policy-version storage (atomic writes, survives restart) | 2 | 2-3 | T11 | Version store |
| T9 | Gateway service: accepts sessions, verifies policy, forwards to cloud | 8 | 3-5 | T2, T4 | Gateway |
| T10 | Cloud API and database (local) | 3 | 4 | T2 | Cloud service |
| T12 | Sensitivity classification: gateway-side flow to level to minimum mode | 3 | 5 | T11 | Classification logic |
| T13 | Capability registry (gateway-registered profile: modes, ML-KEM/ML-DSA sets, memory class, max packet size, firmware, recent results) | 3 | 5-6 | T2 | Registry |
| T14 | Readiness rules: Ready / Partially Ready / Not Ready | 2 | 6 | T13 | Rules and tests |
| T22c | Gateway audit logging and per-device rate limiting | 4 | 6-7 | T22a | Audit log, limiter |
| T23a | Static baselines: Classical, Hybrid, PQC, sensitivity-only | 3 | 7 | T9, T12 | Config-flag baselines |
| T23b | Adaptive baselines: downgrade-on-failure, static retry | 2 | 8 | T20 | Comparison baselines |
| T38 | Final integration and Docker | 5 | 8-10 | T20, T22c | One-command system |
| T36 | Demo script and rehearsal | 2 | 10-11 | T38 | Demo |
| T34 | Gateway and cloud paper sections, architecture diagrams | 3 | 10-11 | T38 | Draft text |
| T37 | Viva prep | 2 | 12 | T34 | Q&A notes |

## 4. Weekly plan

| Week | Hours | Work |
|------|-------|------|
| 1 | 3 | T2 architecture and interface spec |
| 2 | 4 | T11 policy schema (3h); T15 (1h) |
| 3 | 4 | T9 gateway (3h); T15 (1h) |
| 4 | 6 | T9 (3h); T10 cloud (3h) |
| 5 | 6 | T9 finish (2h); T12 (3h); T13 (1h) |
| 6 | 5 | T13 (2h); T14 (2h); T22c (1h) |
| 7 | 6 | T23a (3h); T22c (3h) |
| 8 | 3 | T23b (2h); T38 (1h) |
| 9 | 2 | T38 |
| 10 | 4 | T38 (2h); T36 (1h); paper (1h) |
| 11 | 3 | T36 (1h); paper (2h) |
| 12 | 2 | Viva prep |

Peak weeks: 3-7. Integration returns in weeks 8-11.

## 5. Design notes
- The gateway is trusted in the prototype. It terminates the device-gateway session, enforces policy, and opens a separate ordinary TLS session to the cloud. Do not claim end-to-end confidentiality.
- Sensitivity comes from the signed gateway policy, not from a device label. A device-provided label can never override policy.
- Policy signing authority: a small offline script holds the ML-DSA private key (from S1's module). The gateway only holds the authority public key. Do not build a PKI.
- Version store: write atomically (temp file plus rename or a small database transaction). A gateway restart must not reset the highest accepted version.
- Capability records are gateway-registered, not hardware-attested. Use the phrase "gateway-registered capability".
- Freeze the interface spec after Week 2. Changes go through a team decision.
- Flooding is an optional evaluation, not a module. The rate limiter is enough.

## 6. Interfaces
- **Gets from S1:** KEM, signature, AEAD modules (Week 3-4).
- **Gives S3:** policy schema, version store, sensitivity mapping, registry, and a state-machine hook in the gateway.
- **Gives S4:** gateway audit logs in the agreed schema; baselines runnable by a config flag.

## 7. Definition of done
- Device to gateway to cloud works for all four sensitivity levels.
- Gateway rejects unsigned, stale or unknown-authority policies before use.
- Restart preserves the highest accepted policy version.
- All seven baselines and the full gateway run from config flags.
- One command starts the system; the demo runs without manual fixes.

## 8. Risks and fallbacks
- Interface mismatch with S1: use mock messages until the module is ready; keep a shared test message file.
- Integration late: keep a working end-to-end skeleton from Week 4 and integrate continuously.
- Cloud work grows: keep it minimal; S4 is the backup.

## 9. Viva topics to master
Why the gateway is trusted; how sensitivity is decided; how a policy is verified; what the capability registry does and does not prove; how restart persistence works; what the baselines are.

## 10. Approval
Any policy schema or rules change: you propose it, S3 approves. Interface changes after Week 2: team decision.

---

# Add-on: What to do and how to do it

## A. Suggested stack (pick one and stay with it)
- **Language:** Python 3 with `asyncio` (fastest to build) or Go if the team knows it.
- **Cloud API:** FastAPI plus SQLite.
- **Version store and registry:** SQLite (one file, transactional).
- **Packaging:** Docker Compose with three services: `device-sim`, `gateway`, `cloud`.
- **Tests:** `pytest`; use `curl` for quick manual checks.
- **Gateway to cloud:** ordinary TLS with a self-signed local certificate. This is not a PKI; do not claim one.

## B. Build order (do not skip steps)
1. **Skeleton (Week 3).** Device sim sends a message to the gateway, the gateway forwards to the cloud, the cloud stores it. No crypto yet. Fix the message format from T2: `device_id, flow_id, message_type, payload, timestamp`.
2. **Sessions.** Add a session table (`session_id, device_id, mode, created, last_seen`). Then plug in S1's KEM and AEAD functions.
3. **Policy handling.**
   - Policy is JSON: `flow_id, sensitivity, minimum_mode, policy_version, authority_id`. Sign the canonical bytes (sorted keys, no extra whitespace, UTF-8) so both sides hash identical bytes.
   - The offline signer script produces `policy.json` plus a detached signature using S1's ML-DSA function.
   - Gateway loads a policy only if: signature verifies, authority is trusted, version is greater than the stored highest.
4. **Version store.** One table: `authority_id, highest_version`. Update inside a transaction (`BEGIN IMMEDIATE`), commit before activating the policy. Test: kill the process mid-update, restart, confirm the version did not go backwards.
5. **Sensitivity enforcement.** Gateway looks up `flow_id` in the verified policy. The device's own label is ignored. Compare the negotiated mode against `minimum_mode`; reject if lower. Emit an event for S3's state machine.
6. **Capability registry.** Table: `device_id, supported_modes, kem_set, dsa_set, memory_class, cpu_class, max_packet, firmware, current_mode, recent_results, migration_status`. The gateway consults it before negotiating.
7. **Readiness rules.** Small pure function `readiness(device, flow_policy, recent_results) -> Ready | Partial | Not Ready` with unit tests for each rule from the project description.
8. **Audit log and rate limiting.** Log every connection, rejection and reason as JSON lines. Use a token bucket per device (for example N connections per minute) and log throttled attempts.
9. **Baselines.** One config file with a `mode` field: `static_classical`, `static_hybrid`, `static_pqc`, `sensitivity_only`, `downgrade_on_failure`, `static_retry_with_floor`, `full`. The gateway reads it at start.
10. **Docker and one-command start.** `docker compose up` must start everything. Put ports, keys (test keys only) and config in an `.env`.

## C. Definition of "integrated"
A demo script runs these cases in order and prints PASS or FAIL: valid Critical flow over PQC; Critical flow attempting Classical (rejected); replayed policy (rejected); tampered policy (rejected); restart then replay (still rejected).

## D. Pitfalls
- Building the gateway before the interface spec is frozen.
- Activating a policy before the version is safely stored.
- Trusting a device-supplied sensitivity label.
- Integrating only in the last two weeks: keep the end-to-end skeleton alive from Week 4.

## E. Handoffs
- Week 2: schema and interface spec to everyone.
- Week 4: working skeleton to S1, S3 and S4.
- Week 5-6: sensitivity mapping, registry and state-machine hook to S3.
- Week 7: baselines runnable by config to S4.
