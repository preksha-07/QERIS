"""
QERIS Policy Serialization Boundary
Milestone: Demo 1 — Standalone Signed-Policy Proof of Concept
Author: S1 (Cryptography and Device Engineer)

===============================================================================
ARCHITECTURAL NOTICE & SERIALIZATION BOUNDARY:
1. PROVISIONAL IMPLEMENTATION:
   This module provides a provisional serialization interface strictly for local,
   isolated prototype testing of the signed-policy verification flow.
2. NOT RFC 8785 COMPLIANT:
   This standard-library JSON serialization is NOT claimed to be RFC 8785
   (JSON Canonicalization Scheme / JCS) compliant. Python's json.dumps with
   sorted keys and compact separators does not implement the full number
   formatting or canonicalization requirements of RFC 8785.
3. UNAPPROVED SCHEMA & STORAGE:
   Policy storage format, wire encoding, and canonicalization have NOT been
   approved by S2. S2 owns policy storage and gateway integration. S2's explicit
   approval is mandatory before any integration into the gateway or message envelope.
4. CANDIDATE FIELDS:
   The fields ('version', 'sig_alg', 'flow_to_tier', 'tier_to_suite', 'expiry',
   'revocation_list') are provisional candidate fields inferred from the threat
   model, NOT a finalized or approved production schema.
5. STRICT PARSING & SERIALIZATION RULES:
   - Duplicate keys in JSON objects are strictly rejected.
   - Non-standard JSON constants (NaN, Infinity, -Infinity) are strictly rejected.
   - Unpaired Unicode surrogates are rejected during UTF-8 encoding.
===============================================================================
"""

from collections.abc import Mapping
import json
from typing import Any

# Provisional candidate fields inferred from threat model (pending S2 review)
PROVISIONAL_CANDIDATE_FIELDS: tuple[str, ...] = (
    "version",
    "sig_alg",
    "flow_to_tier",
    "tier_to_suite",
    "expiry",
    "revocation_list",
)


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

    Boundary isolation:
    This function isolates signed-byte generation so that a real RFC 8785
    or CBOR canonicalizer can replace it later without impacting verification logic.

    Deterministic serialization for test fixtures:
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
    Deserializes canonical UTF-8 bytes back into a policy dictionary.
    Rejects malformed JSON, duplicate keys, non-standard constants (NaN/Infinity),
    invalid UTF-8 bytes, and non-object payloads with a ValueError.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes or bytearray, got {type(data).__name__}")

    try:
        decoded_str = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Policy bytes are not valid UTF-8: {exc}") from exc

    try:
        parsed = json.loads(
            decoded_str,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Policy payload is not valid strict JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError(f"Deserialized policy payload must be a JSON object (dict), got {type(parsed).__name__}")
    return parsed
