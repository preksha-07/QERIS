"""
QERIS S2: Canonical JSON Encoder and Policy Digest

Implements strict, deterministic canonical JSON encoding aligned with RFC 8785.
Guarantees that signer and verifier process identical byte streams regardless of
in-memory dictionary key ordering or harmless JSON formatting variations.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from qeris.s2.config import POLICY_DIGEST_DOMAIN_PREFIX


class CanonicalEncodingError(ValueError):
    """Raised when data cannot be canonically encoded."""
    pass


def _validate_safe_types(obj: Any) -> None:
    """Recursively validates that the object only contains safe, standard JSON types."""
    if obj is None or isinstance(obj, (bool, str, int)):
        return
    if isinstance(obj, float):
        import math
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalEncodingError("Float NaN and Infinity are strictly forbidden in canonical JSON")
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_safe_types(item)
        return
    if isinstance(obj, (dict, Mapping)):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalEncodingError(f"Dict keys must be strings, got {type(k).__name__}")
            _validate_safe_types(v)
        return
    raise CanonicalEncodingError(f"Unsupported data type for canonical JSON: {type(obj).__name__}")


def canonical_encode(data: Any) -> bytes:
    """
    Encodes data to deterministic, canonical UTF-8 JSON bytes.

    Properties:
    1. Keys sorted lexicographically at all nesting levels.
    2. Compact separators without extraneous whitespace: (',', ':').
    3. No float conversions for integer values.
    4. Deterministic Unicode escape handling (ensure_ascii=False).
    5. UTF-8 byte stream.
    """
    _validate_safe_types(data)
    try:
        json_str = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return json_str.encode("utf-8")
    except Exception as exc:
        raise CanonicalEncodingError(f"Canonical encoding failed: {exc}") from exc


def compute_policy_digest(policy_data: Any) -> str:
    """
    Computes a deterministic SHA-256 hex digest of the canonical policy bytes
    using domain separation to prevent cross-protocol collision attacks.
    """
    canonical_bytes = canonical_encode(policy_data)
    hasher = hashlib.sha256()
    hasher.update(POLICY_DIGEST_DOMAIN_PREFIX)
    hasher.update(canonical_bytes)
    return hasher.hexdigest()
