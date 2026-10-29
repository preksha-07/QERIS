# S3 - Security Logic and Recovery Engineer (48 hours)

**Project:** Sensitivity-Aware and Failure-Resilient Post-Quantum Migration Gateway
**Contribution:** Cause-classified, security-floor-bounded recovery for post-quantum IoT handshakes
**Teammates:** S1 (crypto/device), S2 (gateway/cloud), S4 (data science)

## 1. Your mission
Own the research contribution: the security-floor state machine, failure classification and recovery, and the protections (replay, downgrade) that keep the floor intact. If your part fails, the project is only engineering.

## 2. Responsibilities
**Primary:** requirements and threat model, security-floor state machine with invariant monitor, failure taxonomy, recovery controller, replay protection, downgrade rejection, attack tests, invention-disclosure notes.
**Secondary:** optional model check, security/state-machine/recovery paper sections (including abstract and contribution statement), viva prep.
**Backup for:** policy signing (S1), policy schema and sensitivity (S2), failure taxonomy support (S4).

## 3. Tasks

| ID | Task | Hours | Weeks | Depends on | Deliverable |
|----|------|-------|-------|------------|-------------|
| T1 | Requirements and threat model | 4 | 1-2 | none | Threat model doc |
| T19 | Failure taxonomy (cause definitions and labels) | 3 | 2-3 | T1 | Taxonomy |
| T18 | Security-floor state machine and invariant monitor | 10 | 3-6 | T1, T12 | Spec, code, invariant tests |
| T16 | Replay protection, including fast-forward bound | 4 | 4-5 | T5, T15 | Replay logic and tests |
| T17 | Downgrade rejection | 3 | 5 | T12 | Downgrade logic and tests |
| T20 | Recovery controller: cause-specific and floor-bounded | 8 | 7-8 | T18, T19 | Controller and tests |
| T25 | Attack tests | 5 | 8-10 | T16, T17 | Attack test report |
| T26 | State-machine model check (optional, simplify-second) | 2 | 9 | T18 | Model and result |
| T27 | Invention-disclosure notes | 2 | 10 | T20 | Notes for IP office |
| T34 | Paper: abstract, threat model, security analysis, state machine, recovery | 5 | 10-11 | T25 | Draft text |
| T37 | Viva prep | 2 | 12 | T34 | Q&A notes |

## 4. Weekly plan

| Week | Hours | Work |
|------|-------|------|
| 1 | 3 | T1 threat model |
| 2 | 3 | T1 finish (1h); T19 taxonomy (2h) |
| 3 | 4 | T19 (1h); T18 state-machine spec (3h) |
| 4 | 5 | T18 build (3h); T16 replay (2h) |
| 5 | 6 | T16 (2h); T17 (3h); T18 (1h) |
| 6 | 3 | T18 finish and invariant monitor (3h) |
| 7 | 4 | T20 recovery controller (4h) |
| 8 | 5 | T20 (4h); T25 (1h) |
| 9 | 5 | T25 (3h); T26 (2h) |
| 10 | 5 | T25 (1h); T27 (2h); paper (2h) |
| 11 | 3 | Paper |
| 12 | 2 | Viva prep |

Peak weeks: 4-10.

## 5. The seven invariants (each needs a test)
1. A flow never becomes active below its signed minimum security floor.
2. An invalid, stale or untrusted policy cannot authorize a transition.
3. A transport retry cannot change the security floor.
4. A recovery action cannot convert a cryptographic failure into a transport failure.
5. A gateway restart cannot erase replay-protection state.
6. A device-provided flow label cannot override gateway policy.
7. An observed network failure cannot authorize an insecure downgrade.

## 6. Design notes
- **States (suggested):** Unregistered, Registered, PolicyValid, Negotiating, Active(mode), DegradedTransport, Quarantined. Transitions have guards on signature, authority, version, capability and floor. Transport failures may only move to DegradedTransport, never lower the mode.
- **Failure causes:** loss/timeout, MTU/fragmentation, resource/compute (only if observed in Week-1 and pilot data), security failure. Security failures are rejected, logged, and possibly quarantined.
- **Recovery:** each cause gets an allowed action set (bounded retry, adaptive timeout, fragment size, delay, queue). A security failure never triggers a retry-with-weaker-mode.
- **Feasibility check:** if the floor is unreachable for a device, report "floor unreachable" rather than retrying forever.
- **Replay:** accept only valid signature, trusted authority, and version greater than the persisted highest. Add a bound on how far a version may jump, or scope it to the authority, to resist a fast-forward attack that would freeze future updates.
- **Conditional class:** if compute failures do not appear in Week-1 and pilot data, drop that class and say so honestly in the paper.
- **Prior-art positioning:** cause-based handshake adaptation, minimum-strength enforcement and TUF-style version checks exist. Your claim is the combination and the floor-bounded recovery guarantee, not any single piece.

## 7. Interfaces
- **Gets from S1:** signature verification results and failure reasons.
- **Gets from S2:** policy schema, version store, sensitivity mapping, registry, gateway hook.
- **Gives S4:** cause labels and event schema for classification accuracy; state-machine event logs.
- **Gives S2:** recovery controller interface for integration and adaptive baselines.

## 8. Definition of done
- All seven invariants have passing tests.
- Every attack test (invalid signature, modified policy, replayed policy, downgrade, fake handshakes) is rejected and logged.
- Recovery never activates a flow below its floor across all injected failures.
- Classifier reports a confusion matrix against injected ground truth.
- Threat model states what is out of scope.

## 9. Risks and fallbacks
- Causes not distinguishable: report the result honestly and merge classes.
- Compute failures not observed: drop the class.
- Recovery controller late: ship the state machine with a simpler bounded-retry controller and label the limitation.
- Prior-art conflict from mentor or IP office: reposition to floor-bounded recovery.

## 10. Viva topics to master
Why the floor exists and what signs it; each invariant and its test; why recovery cannot downgrade; how replay protection survives restart; how you separate transport from crypto failures; what you did not prove.

## 11. Approval
You own state-machine changes. S2 reviews them, and invariant tests must pass. You approve policy schema changes proposed by S2. Nothing about the patent or disclosure goes public without the mentor, all four students and the IP office.

---

# Add-on: What to do and how to do it

## A. Threat model (Week 1-2)
Write one page covering: assets (policy authority key, gateway keys, session keys, replay store), attacker abilities (drop, delay, duplicate, reorder, replay and modify network messages; control a device; cannot break ML-KEM or ML-DSA), trust assumptions (gateway trusted, policy authority trusted), and explicit out-of-scope items (hardware attestation, PKI, end-to-end confidentiality, complete DoS protection).

## B. State machine (Week 3-6)
1. Write the spec first as a table: `state, event, guard, next_state, action`.
2. Implement it as a **pure function** `transition(state, event, context) -> (new_state, actions)`. No I/O inside. The gateway calls it and performs the actions.
3. Put invariant checks in a monitor that runs after every transition. On any violation, raise, log, and move the flow to Quarantined.
4. Suggested events: `PolicyVerified`, `PolicyRejected`, `HandshakeStarted`, `HandshakeOk`, `TransportFailure(cause)`, `SecurityFailure(reason)`, `FloorUnreachable`, `Restart`.
5. Tests: one test per invariant. Then **property-based tests** (for example the `hypothesis` library in Python): generate random event sequences and assert that no flow is ever Active below its floor.

## C. Failure taxonomy and classifier (Week 2-4, 7)
Start with a rule table that maps observable signals to a cause:

| Signal | Likely cause |
|--------|--------------|
| No response, retransmit timer expires, fragments missing | loss/timeout |
| Fragment count or size exceeds path MTU, fragments repeatedly dropped | MTU/fragmentation |
| Peer alive but response arrives only after a long delay, long key-generation time reported | resource/compute (only if observed) |
| Bad signature, unknown authority, stale version, mode below floor | security failure |

Record the signals with each event so S4 can compare your label with the injected ground truth.

## D. Recovery controller (Week 7-8)
For each cause define the allowed actions and a hard bound:
- loss/timeout: bounded retry with backoff; give up after N tries and report.
- MTU: smaller fragment size, then retry.
- compute: longer timeout budget, then retry (only if the class exists).
- security failure: reject, log, possibly quarantine. Never retry with weaker settings.
Before executing any action, the controller asks the state machine: "does this action keep the mode at or above the floor?" If not, refuse.
Also implement the feasibility check: if the device cannot support the floor, return `FloorUnreachable` and stop retrying.

## E. Replay and downgrade (Week 4-5)
- Replay: accept only if signature valid, authority trusted, `incoming_version > persisted_highest`. Add a maximum allowed jump (for example a configured step) so an attacker or a mistake cannot set an enormous version and freeze future updates.
- Downgrade: compare the negotiated mode against the floor from the verified policy, never against anything the device claims.

## F. Attack tests (Week 8-10)
Script each attack and record expected and actual outcomes: invalid signature; modified policy; replayed policy; equal version; downgrade attempt on a Critical flow; unknown authority; fake handshakes; restart then replay; policy update during an active session. Every case should produce a rejection and a log line.

## G. Optional model check (Week 9)
Model the transition table in TLA+ or SPIN with a lossy, duplicating network, and check the invariants. If it takes more than two hours to get going, drop it.

## H. Invention notes (Week 10)
Write a short factual description: the problem, the mechanism (cause classification, floor-bounded action set, unreachable-floor check), and what differs from existing work (see the prior-art report). Give it to your mentor and IP office. Do not publish or post anything first.

## I. Pitfalls
- Letting the controller decide on its own that a downgrade is acceptable.
- Mixing I/O into the state machine so it cannot be tested.
- Claiming the classifier is accurate without ground truth.

## J. Handoffs
- Week 3: taxonomy to S4.
- Week 6: state-machine hook to S2.
- Week 8: controller interface to S2 (for adaptive baselines) and S4 (for runs).
