# QERIS S4 Integration and Shared Logging Contract

**Version:** 1.0.0  
**Status:** Integrated Specification  
**Components:** S1 (Cryptography), S2 (Gateway), S3 (Security & Recovery), S4 (Data Science & Analytics)

---

## 1. Executive Summary

This document specifies the shared logging contract and data ingestion pipeline connecting the operational QERIS components (S1, S2, S3) with the evaluation and analysis framework (S4).

Through the `GatewayLogBridge`, runtime audit records emitted by `qeris/s2/gateway.py` are mapped into the canonical S4 `LogRecord` format without loss of metadata or security classification integrity.

---

## 2. Shared Logging Contract

### 2.1 Runtime Gateway Audit Log Schema (`gateway_logs.jsonl`)

Every flow access evaluation and cryptographic session operation in S2 generates an immutable structured JSON entry with the following fields:

| Field Name | Type | Description |
|:---|:---|:---|
| `trace_id` | string | Unique UUIDv4 transaction identifier tying requests to decisions. |
| `ts` | integer | UTC timestamp in milliseconds since Unix epoch. |
| `timestamp` | string | ISO 8601 formatted UTC timestamp with timezone. |
| `device_id` | string | Unique identifier of the requesting client or IoT device. |
| `flow_id` | string | Target telemetry or control flow identifier. |
| `sensitivity` | string | Sensitivity tier: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `minimum_mode` | string | Minimum required cryptographic security mode: `CLASSICAL`, `HYBRID`, `PQC`. |
| `requested_mode` | string | Cryptographic mode requested by the client endpoint. |
| `policy_version` | integer | Policy sequence version verified against the monotonic store. |
| `authority_id` | string | Issuer authority identifier verified via ML-DSA-65. |
| `decision` | string | Final gateway disposition: `ALLOW`, `REJECT`, or `FLOOR_UNREACHABLE`. |
| `reason` | string | Human-readable explanation and operational root cause. |
| `s3_verdict` | string | Decision from S3 Recovery Controller: `NONE`, `SUCCESS`, `DISCARD_AND_LOG`, `RETRY`, `QUARANTINED`, `FLOOR_UNREACHABLE`. |
| `cause_label` | string | Taxonomy classification label: `none`, `security_failure`, `mtu_fragment`, `loss_timeout`. |
| `security_reason` | string/null | Specific security invariant violation code (e.g. `mode_below_floor`, `bad_signature`). |
| `crypto_status` | string | Cryptographic execution status: `SKIPPED`, `VERIFIED_ROUNDTRIP`, `REJECTED_BEFORE_SESSION`, `UNSUPPORTED_MODE`, `ERROR`. |

---

## 3. Field Mapping to S4 Canonical `LogRecord`

The `GatewayLogBridge` maps runtime gateway entries to S4 `LogRecord` fields as follows:

| Gateway Audit Field | S4 `LogRecord` Field | Conversion Rule / Default |
|:---|:---|:---|
| `ts` | `ts` | Passed directly as epoch milliseconds. |
| `trace_id` | `run_id` | Formatted as `"{run_id}:{trace_id}"` for traceability. |
| (derived) | `scenario` | Defaults to `"live_gateway"` (`"legacy_entry"` for historical records). |
| (config) | `baseline` | Configurable baseline strategy (default: `"full_gateway"`). |
| `device_id` | `device_id` | Passed directly. |
| (config) | `device_class` | Target hardware profile (default: `"edge_gateway"`). |
| `flow_id` | `flow_id` | Passed directly. |
| `sensitivity` | `sensitivity` | Normalized to `SensitivityTier` enum values. |
| `crypto_status`, `s3_verdict` | `event` | Mapped to `LogEvent` (`handshake_complete`, `failure`, `retry`, `quarantine`). |
| `requested_mode` | `mode` | Mapped to `CryptoMode` (`CLASSICAL`, `HYBRID`, `PQC`, `NONE`). |
| `cause_label` | `cause_label` | Passed directly from S3 classification output. |
| (constant) | `cause_injected` | Set to `"none"` (live events reflect real traffic, not synthetic faults). |
| (config) | `size_bytes` | Payload and certificate wire size in bytes. |
| (config) | `duration_ms` | Elapsed handshake latency in milliseconds. |
| (config) | `cpu_pct` | Hardware CPU utilization estimate. |
| (config) | `mem_mb` | Memory usage estimate in MB. |
| `decision` | `outcome` | Mapped: `ALLOW` $\to$ `SUCCESS`, `REJECT` $\to$ `REJECT`, `FLOOR_UNREACHABLE` $\to$ `FLOOR_UNREACHABLE`. |

---

## 4. Failure Classification and Security Reason Mapping

S3 failure taxonomy assigns `cause_label` and `security_reason` using strict priority:

$$\text{SECURITY\_FAILURE} > \text{MTU\_FRAGMENT} > \text{LOSS\_TIMEOUT} > \text{COMPUTE}$$

### S3 to S4 Taxonomy Alignment Table

| Runtime Signal | `cause_label` | `security_reason` | S4 Confusion Class |
|:---|:---|:---|:---|
| ML-DSA-65 signature failure | `security_failure` | `bad_signature` | `security_failure` |
| Untrusted authority ID | `security_failure` | `unknown_authority` | `security_failure` |
| Monotonic rollback attempt | `security_failure` | `replayed_version` | `security_failure` |
| Version jump overflow | `security_failure` | `fast_forward_version` | `security_failure` |
| Requested mode < policy floor | `security_failure` | `mode_below_floor` | `security_failure` |
| Unregistered device | `security_failure` | `auth_check_failed` | `security_failure` |
| MTU size or fragment count exceeded | `mtu_fragment` | `None` | `mtu_fragment` |
| Retransmission timeout / loss | `loss_timeout` | `None` | `loss_timeout` |
| Clean verification & handshake | `none` | `None` | `none` |

---

## 5. Supported Evaluation Workflows

The integrated S4 bridge supports three distinct analytical workflows:

1. **Live Gateway Stream Ingestion:**
   ```python
   from qeris.s4.gateway_log_bridge import GatewayLogBridge
   bridge = GatewayLogBridge()
   log_table = bridge.ingest_file("qeris/s2/gateway_logs.jsonl")
   ```

2. **Classification Accuracy & Confusion Matrix:**
   ```python
   from qeris.s4.analysis import StatisticalAnalyzer
   matrix = StatisticalAnalyzer.evaluate_classifier(log_table)
   print("Overall Accuracy:", matrix.accuracy)
   print("Security F1 Score:", matrix.per_class["security_failure"].f1)
   ```

3. **Baseline Comparative Summary & Floor Audit:**
   ```python
   summary = StatisticalAnalyzer.summarize_baselines(log_table)
   assert summary["full_gateway"]["floor_violations"] == 0
   ```

---

## 6. Verification and Integration Test Results

The S4 gateway bridge is thoroughly verified by `qeris/s4/test_gateway_log_bridge.py`:

- **Phase-4 Structured Record Parsing:** 7 unit tests covering `ALLOW`, `REJECT`, `FLOOR_UNREACHABLE`, and crypto roundtrips.
- **Legacy Record Backward Compatibility:** 4 unit tests verifying safe timestamp and heuristic inference for historical logs.
- **Heuristic Inference Engine:** 8 unit tests covering all reason classifications.
- **File and Stream Ingestion:** 7 unit tests verifying mixed logs, error handling, and `StatisticalAnalyzer` compatibility.
- **Total Bridge Tests:** 26/26 passed in 0.09s.
