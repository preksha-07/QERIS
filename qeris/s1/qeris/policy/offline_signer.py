"""Offline ML-DSA-65 policy authority tooling for QERIS S1.

The secret authority key is used only by this offline command. The gateway
receives signed envelopes and the authority public key; it must never receive
or load the authority secret key.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from typing import Any

import oqs

from .signed_policy import (
    DEFAULT_SIG_ALG,
    create_signed_envelope,
    validate_policy_structure,
)

SIGNING_ALGORITHM = DEFAULT_SIG_ALG  # ML-DSA-65


def _atomic_write(path: Path, data: bytes, *, private: bool = False, overwrite: bool = False) -> None:
    """Write a file atomically; private files get owner-only permissions on POSIX."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")

    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        if private and os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {path}")
        os.replace(temp_path, path)
        if private and os.name == "posix":
            path.chmod(0o600)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def generate_authority_keypair(
    output_prefix: str | Path = "authority_root", *, overwrite: bool = False
) -> tuple[Path, Path]:
    """Generate an ML-DSA-65 authority keypair for offline custody.

    The secret key is written with owner-only permissions on POSIX. Existing
    key files are never overwritten unless the caller explicitly opts in.
    """
    prefix = Path(output_prefix)
    priv_path = Path(f"{prefix}.key")
    pub_path = Path(f"{prefix}.pub")
    if not overwrite and (priv_path.exists() or pub_path.exists()):
        raise FileExistsError("Authority key output already exists; choose a new prefix or explicitly rotate it")

    with oqs.Signature(SIGNING_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    # Write public first, then secret. Never print or return secret bytes.
    _atomic_write(pub_path, public_key, overwrite=overwrite)
    try:
        _atomic_write(priv_path, secret_key, private=True, overwrite=overwrite)
    except Exception:
        # Avoid leaving a misleading half-pair behind.
        pub_path.unlink(missing_ok=True)
        raise
    return priv_path, pub_path


def _load_policy_records(data: Any) -> list[tuple[str, dict[str, Any]]]:
    """Normalize a single policy or flow-keyed policy bundle and validate it."""
    records: list[tuple[str, dict[str, Any]]] = []
    if not isinstance(data, dict):
        raise ValueError("Policy input must be a JSON object")

    if "flow_id" in data:
        policy = dict(data)
        validate_policy_structure(policy, raise_exception=True)
        records.append((policy["flow_id"], policy))
    else:
        if not data:
            raise ValueError("Policy bundle must contain at least one flow")
        for bundle_flow_id, flow_body in data.items():
            if not isinstance(bundle_flow_id, str) or not bundle_flow_id.strip():
                raise ValueError("Every policy bundle key must be a non-empty flow ID")
            if not isinstance(flow_body, dict):
                raise ValueError(f"Policy entry for {bundle_flow_id!r} must be an object")
            policy = dict(flow_body)
            policy.setdefault("flow_id", bundle_flow_id)
            if policy["flow_id"] != bundle_flow_id:
                raise ValueError(f"Bundle key {bundle_flow_id!r} does not match policy flow_id {policy['flow_id']!r}")
            validate_policy_structure(policy, raise_exception=True)
            records.append((bundle_flow_id, policy))
    return records


def sign_policy_file(
    input_policy_path: Path,
    authority_secret_key_path: Path,
    output_path: Path,
    authority_id: str | None = None,
    *,
    overwrite: bool = False,
) -> None:
    """Sign a canonical single policy or flow bundle into JSON envelopes."""
    input_policy_path = Path(input_policy_path)
    authority_secret_key_path = Path(authority_secret_key_path)
    output_path = Path(output_path)
    if not input_policy_path.is_file():
        raise FileNotFoundError(f"Input policy file not found: {input_policy_path}")
    if not authority_secret_key_path.is_file():
        raise FileNotFoundError(f"Authority secret key not found: {authority_secret_key_path}")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing output: {output_path}")

    try:
        data = json.loads(input_policy_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Policy input is not valid UTF-8 JSON: {exc}") from exc
    records = _load_policy_records(data)

    # Enforce the requested authority ID instead of silently ignoring the CLI option.
    if authority_id is not None:
        if not isinstance(authority_id, str) or not authority_id.strip():
            raise ValueError("authority_id must be a non-empty string")
        for flow_id, policy in records:
            if policy["authority_id"] != authority_id:
                raise ValueError(
                    f"Policy {flow_id!r} authority_id {policy['authority_id']!r} does not match requested {authority_id!r}"
                )

    secret_key = authority_secret_key_path.read_bytes()
    if not secret_key:
        raise ValueError("Authority secret key file is empty")

    envelopes: dict[str, Any] = {}
    for flow_id, policy in records:
        envelopes[flow_id] = create_signed_envelope(
            policy, secret_key, sig_alg=SIGNING_ALGORITHM
        )

    output_bytes = (json.dumps(envelopes, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(output_path, output_bytes, overwrite=overwrite)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QERIS offline ML-DSA-65 policy authority tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_parser = subparsers.add_parser("genkey", help="Generate an offline ML-DSA-65 authority keypair")
    gen_parser.add_argument("--prefix", default="authority_root", help="Output prefix for .key and .pub")
    gen_parser.add_argument("--overwrite", action="store_true", help="Explicitly overwrite existing key files (key rotation)")

    sign_parser = subparsers.add_parser("sign", help="Sign a policy JSON file offline")
    sign_parser.add_argument("--input", required=True, help="Input canonical policy JSON")
    sign_parser.add_argument("--key", required=True, help="Offline authority secret-key file")
    sign_parser.add_argument("--output", required=True, help="Output signed-envelope JSON")
    sign_parser.add_argument("--authority-id", help="Require every policy to use this authority_id")
    sign_parser.add_argument("--overwrite", action="store_true", help="Explicitly overwrite output file")

    args = parser.parse_args(argv)
    try:
        if args.command == "genkey":
            priv, pub = generate_authority_keypair(args.prefix, overwrite=args.overwrite)
            print(f"Generated {SIGNING_ALGORITHM} authority keypair.")
            print(f"Secret key (KEEP OFFLINE): {priv}")
            print(f"Public key: {pub}")
        elif args.command == "sign":
            sign_policy_file(
                Path(args.input), Path(args.key), Path(args.output),
                authority_id=args.authority_id, overwrite=args.overwrite,
            )
            print(f"Signed policy file successfully: {args.output}")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
