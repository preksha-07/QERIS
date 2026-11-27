# QERIS S1 — Cryptographic Object Sizes & Link MTU Handover

**Document Version:** 1.0.0
**Date:** 2026-11-26
**Status:** Canonical S1 Handover to S2 / S4
**Scope:** Cryptographic Byte Sizes, Wire Overhead, and Theoretical Fragmentation Models

---

## 1. Executive Summary & Purpose

This document provides the authoritative cryptographic object sizes implemented and verified in QERIS Step 1 (S1). It serves as the input specification for S2 transport adapters and S4 fragmentation evaluation models.

> [!IMPORTANT]
> **PHYSICAL MEASUREMENT STATUS: PENDING HARDWARE (UNVERIFIED)**
> All MTU fragmentation metrics and packet count estimates in this document are **mathematical and theoretical derivations** based on standard link-layer payload limits.
> **No physical radio packet captures, Wireshark/pcap captures, or 802.15.4/BLE sniffer traces have been conducted.**
> Neither S1 nor the local simulator claims to provide physical hardware fragmentation measurements.

---

## 2. Authoritative Cryptographic Object Sizes

The following table details the exact byte lengths of keys, ciphertexts, signatures, and overhead implemented across all S1 cryptographic modules:

| Primitive / Construction | Role / Profile | Public Key / Share (Bytes) | Ciphertext / Share (Bytes) | Secret Key (Bytes) | Shared Secret (Bytes) | Signature Size (Bytes) |
|---|---|---|---|---|---|---|
| **ML-KEM-512** (FIPS 203) | `DeviceProfile.PQC` | $800$ | $768$ | $1,632$ | $32$ | N/A |
| **ML-KEM-768** (FIPS 203) | Sub-component in Hybrid | $1,184$ | $1,088$ | $2,400$ | $32$ | N/A |
| **X25519** (RFC 7748) | `DeviceProfile.CLASSICAL` | $32$ | $32$ | $32$ | $32$ | N/A |
| **X25519MLKEM768** (RFC 10024 / 9958) | `DeviceProfile.HYBRID` | $1,216$ | $1,120$ | $2,432$ | $64$ | N/A |
| **ML-DSA-65** (FIPS 204) | Offline Policy Authority | $1,952$ | N/A | $4,032$ | N/A | $3,309$ |
| **Ed25519** (RFC 8032) | Device Authentication | $32$ | N/A | $32$ | N/A | $64$ |
| **AES-256-GCM** (SP 800-38D) | Telemetry Payload Protection | N/A | Variable ($L$) | $32$ | N/A | Tag: $16$ B; Nonce: $12$ B |

### 2.1 Handshake Wire Exchange Summary
The total raw cryptographic payload exchanged across the initial handshake request and response (excluding transport framing) is:
- **Classical (X25519):** $32 + 32 = 64\text{ bytes}$.
- **PQC (ML-KEM-512):** $800 + 768 = 1,568\text{ bytes}$.
- **Hybrid (X25519MLKEM768):** $1,216 + 1,120 = 2,336\text{ bytes}$.

---

## 3. Theoretical Link-Layer MTU & Fragmentation Analysis

To assess the operational feasibility of post-quantum handshakes on constrained edge networks, theoretical packet fragmentation is calculated across three standard IoT physical/data-link layers:

### 3.1 Standard Link-Layer MTU Limits
1. **Ethernet / Wi-Fi (IEEE 802.3 / 802.11):**
   - Maximum Transmission Unit (MTU): $1,500\text{ bytes}$.
   - Typical IP/UDP overhead: $28\text{ bytes}$ (IPv4) or $48\text{ bytes}$ (IPv6).
   - Maximum Datagram Payload: $\approx 1,472\text{ bytes}$.
2. **IEEE 802.15.4 (6LoWPAN / Thread / Zigbee):**
   - Maximum Physical Layer Packet Data Unit (PSDU): $127\text{ bytes}$.
   - MAC Layer Header & Security Overhead: $\approx 25\text{ bytes}$.
   - 6LoWPAN Unfragmented MTU: $\approx 102\text{ bytes}$.
   - Subsequent 6LoWPAN Fragment Payload: $\approx 80\text{ bytes}$.
3. **Bluetooth Low Energy (BLE 4.2 / 5.0):**
   - Default ATT MTU (Legacy BLE 4.0): $23\text{ bytes}$ ($20\text{ bytes}$ payload).
   - Negotiated ATT MTU with Data Length Extension (DLE): Up to $251\text{ bytes}$ ($244\text{ bytes}$ payload).

### 3.2 Theoretical Fragment Count Matrix

The table below presents the mathematically required fragment counts to transmit the initial client key share and server response:

| Profile | Message Phase | Raw Crypto Payload (Bytes) | Ethernet ($1,472\text{ B}$ Payload) | 6LoWPAN ($80\text{ B}$ Fragment) | BLE DLE ($244\text{ B}$ Payload) |
|---|---|---|---|---|---|
| **Classical** | Client Key Share | $32$ | 1 packet | 1 packet | 1 packet |
| | Server Key Share | $32$ | 1 packet | 1 packet | 1 packet |
| **PQC (ML-KEM-512)** | Client Public Key | $800$ | 1 packet | 10 fragments | 4 fragments |
| | Server Ciphertext | $768$ | 1 packet | 10 fragments | 4 fragments |
| **Hybrid (X25519MLKEM768)** | Client Key Share | $1,216$ | 1 packet | 16 fragments | 5 fragments |
| | Server Key Share | $1,120$ | 1 packet | 14 fragments | 5 fragments |
| **Policy Envelope (ML-DSA-65)** | Signed Policy Bundle | $\approx 5,500$ | 4 packets | 69 fragments | 23 fragments |

---

## 4. Handover Guidelines for S2 & S4

### 4.1 Transport Guidelines for S2 Gateway
1. **UDP / CoAP Transports:**
   - For Ethernet/Wi-Fi: Both Classical and ML-KEM-512 client public keys fit within a single unfragmented $1,500\text{-byte}$ UDP datagram.
   - For Hybrid ($1,216\text{ B}$ share): A single UDP datagram over IPv4 will not fragment at the IP layer on standard $1,500\text{-byte}$ MTU links ($1,216 + 28 = 1,244 \le 1,500$).
   - Over 6LoWPAN / 802.15.4: S2 must configure a reliable block-transfer mechanism (e.g., CoAP Block-Wise Transfer, RFC 7959) or rely on 6LoWPAN adaptation layer fragmentation.
2. **Defensive Upper Bound:**
   - S1 enforces a strict defensive envelope cap of $1\text{ MiB}$ ($1,048,576\text{ bytes}$) in `secure_message.py` to prevent memory exhaustion DoS attacks on receivers.

### 4.2 Measurement Instructions for S4 Evaluation Team
When physical hardware (ESP32 testbench) becomes accessible:
1. Conduct packet captures using a dedicated network tap or IEEE 802.15.4 protocol analyzer (e.g., nRF Sniffer).
2. Measure physical on-the-wire airtime, transmission retry rates, and fragment loss probability under realistic RF noise.
3. Replace the theoretical values in Section 3.2 with measured empirical distributions.
