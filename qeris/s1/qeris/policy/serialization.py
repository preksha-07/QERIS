"""
QERIS Policy Serialization Boundary
Milestone: Complete Backend Integration (S1-S2 Policy Schema Alignment)
Author: S1 (Cryptography and Device Engineer) & S2 (Gateway Engineer)

===============================================================================
ARCHITECTURAL NOTICE & CANONICAL POLICY SCHEMA:
1. CANONICAL FIVE-FIELD POLICY:
   The policy format is standardized on S2's five-field flow policy schema:
   - flow_id: str
   - sensitivity: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
   - minimum_mode: str ("CLASSICAL", "HYBRID", "PQC")
   - policy_version: int (>= 1)
   - authority_id: str
2. DETERMINISTIC SERIALIZATION:
   Deterministic canonical byte serialization for signing and verification:
   - UTF-8 encoded
   - Sorted dictionary keys (sort_keys=True)
   - Compact separators without whitespace (',', ':')
   - ensure_ascii=False to preserve raw UTF-8 codepoints consistently
   - allow_nan=False to reject non-JSON float representations (NaN, Infinity)
   - Rejects non-JSON types, duplicate keys, and unpaired surrogates cleanly.
3. SIGNATURE ENVELOPE DECOUPLING:
   Signature metadata (sig_alg, signature) is stored in an explicit outer envelope,
   keeping the signed canonical policy payload clean.
===============================================================================
"""

from collections.abc import Mapping
import json
from typing import Any

# Canonical five-field policy schema mandated by S2
CANONICAL_POLICY_FIELDS: tuple[str, ...] = (
    "flow_id",
    "sensitivity",
    "minimum_mode",
    "policy_version",
    "authority_id",
)

# Backwards compatibility alias for provisional imports
PROVISIONAL_CANDIDATE_FIELDS = CANONICAL_POLICY_FIELDS


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """
    Object pairs hook for json.loads that rejects duplicate keys.
    Applied recursively to all JSON objects.
    """
    result: dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise ValueError(f"Duplicate key in JSON object: {key!r}")
        result[key] = val
    return result


def _reject_json_constant(constant: str) -> None:
    """
    Parse constant hook for json.loads that strictly rejects non-standard JSON
    constants (NaN, Infinity, -Infinity).
    """
    raise ValueError(f"Non-standard JSON constant rejected: {constant!r}")


def serialize_policy_to_bytes(policy: Mapping[str, Any]) -> bytes:
    """
    Serializes a policy dictionary into canonical UTF-8 bytes for signing.

    Deterministic serialization guarantees:
    - UTF-8 encoded
    - Sorted dictionary keys (sort_keys=True)
    - Compact separators without whitespace (',', ':')
    - ensure_ascii=False to preserve raw UTF-8 codepoints consistently
    - allow_nan=False to reject non-JSON float representations (NaN, Infinity)
    - Rejects unsupported non-JSON types and unpaired surrogates cleanly (raises ValueError)
    """
    if not isinstance(policy, Mapping):
        raise TypeError(f"Policy must be a Mapping, got {type(policy).__name__}")

    try:
        json_str = json.dumps(
            dict(policy),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return json_str.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"Policy serialization failed: {exc}") from exc


def deserialize_policy_from_bytes(data: bytes) -> dict[str, Any]:
    """
    Deserializes raw UTF-8 policy bytes into a Python dictionary.

    Enforces strict JSON parsing rules:
    - Rejects duplicate keys in any JSON object.
    - Rejects non-standard constants (NaN, Infinity, -Infinity).
    - Validates UTF-8 decoding cleanly.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")

    raw_bytes = bytes(data)
    if not raw_bytes:
        raise ValueError("Cannot deserialize empty bytes.")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid UTF-8 byte sequence in policy data: {exc}") from exc

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Policy JSON deserialization failed: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError(f"Policy payload must deserialize to a JSON object (dict), got {type(parsed).__name__}")

    return parsed


def serialize_envelope_to_bytes(envelope: Mapping[str, Any]) -> bytes:
    """Serializes a signed policy envelope into compact UTF-8 JSON bytes."""
    if not isinstance(envelope, Mapping):
        raise TypeError(f"Envelope must be a Mapping, got {type(envelope).__name__}")
    try:
        json_str = json.dumps(
            dict(envelope),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return json_str.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"Envelope serialization failed: {exc}") from exc


def deserialize_envelope_from_bytes(data: bytes) -> dict[str, Any]:
    """Deserializes raw UTF-8 envelope bytes with strict JSON parsing."""
    return deserialize_policy_from_bytes(data)
