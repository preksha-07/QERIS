"""
QERIS S2: Configuration and Cryptographic Constants

Defines configuration parameters, default paths, baseline modes, security modes,
and approved security profile mappings for the S2 Gateway and Cloud services.
"""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Final

# Base directories
S2_DIR: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = S2_DIR.parent.parent

# Database and Log Paths
DEFAULT_POLICY_DB_PATH: Final[str] = os.getenv("QERIS_POLICY_DB_PATH", str(S2_DIR / "policy_store.db"))
DEFAULT_REGISTRY_DB_PATH: Final[str] = os.getenv("QERIS_REGISTRY_DB_PATH", str(S2_DIR / "device_registry.db"))
DEFAULT_CLOUD_DB_PATH: Final[str] = os.getenv("QERIS_CLOUD_DB_PATH", str(S2_DIR / "cloud_telemetry.db"))
DEFAULT_AUDIT_LOG_PATH: Final[str] = os.getenv("QERIS_AUDIT_LOG_PATH", str(S2_DIR / "gateway_audit.jsonl"))

# Cloud Service Config
DEFAULT_CLOUD_HOST: Final[str] = os.getenv("QERIS_CLOUD_HOST", "127.0.0.1")
DEFAULT_CLOUD_PORT: Final[int] = int(os.getenv("QERIS_CLOUD_PORT", "8001"))
DEFAULT_CLOUD_URL: Final[str] = os.getenv("QERIS_CLOUD_URL", f"https://{DEFAULT_CLOUD_HOST}:{DEFAULT_CLOUD_PORT}")
DEFAULT_CLOUD_CA_CERT: Final[str] = os.getenv("QERIS_CLOUD_CA_CERT", str(S2_DIR / "certs" / "cloud_cert.pem"))

# Gateway Service Config
DEFAULT_GATEWAY_HOST: Final[str] = os.getenv("QERIS_GATEWAY_HOST", "0.0.0.0")
DEFAULT_GATEWAY_PORT: Final[int] = int(os.getenv("QERIS_GATEWAY_PORT", "8000"))
DEFAULT_GATEWAY_URL: Final[str] = os.getenv("QERIS_GATEWAY_URL", f"http://{DEFAULT_GATEWAY_HOST}:{DEFAULT_GATEWAY_PORT}")
DEFAULT_ADMIN_API_KEY: Final[Optional[str]] = os.getenv("QERIS_ADMIN_API_KEY", None)

# Cryptographic Signatures (ML-DSA-65 / FIPS 204)
DEFAULT_SIG_ALG: Final[str] = "ML-DSA-65"
DEFAULT_ALLOWED_SIG_ALGS: Final[tuple[str, ...]] = ("ML-DSA-65",)
DEFAULT_AUTHORITY_ID: Final[str] = "QERIS-GATEWAY-AUTH-01"

# Domain Separation for Policy Digests
POLICY_DIGEST_DOMAIN_PREFIX: Final[bytes] = b"QERIS-POLICY-v1:"

# Security Modes (Ordered strictly: CLASSICAL < HYBRID < PQC)
class SecurityMode(str, Enum):
    CLASSICAL = "CLASSICAL"
    HYBRID    = "HYBRID"
    PQC       = "PQC"

MODE_RANK: Final[dict[str, int]] = {
    SecurityMode.CLASSICAL.value: 1,
    SecurityMode.HYBRID.value:    2,
    SecurityMode.PQC.value:       3,
    "PQ":                         3,  # S3 alias
}

# Sensitivity Tiers
class SensitivityTier(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

# Standard Approved Security Profiles
class SecurityProfile(str, Enum):
    CLASSICAL_ECDH_AESGCM     = "CLASSICAL_ECDH_AESGCM"
    HYBRID_X25519_MLKEM_AESGCM = "HYBRID_X25519_MLKEM_AESGCM"
    PQC_MLKEM512_AESGCM        = "PQC_MLKEM512_AESGCM"
    PQC_MLKEM768_AESGCM        = "PQC_MLKEM768_AESGCM"
    PQC_MLKEM1024_AESGCM       = "PQC_MLKEM1024_AESGCM"

# Mapping from Profile to Mode
PROFILE_TO_MODE: Final[dict[str, str]] = {
    SecurityProfile.CLASSICAL_ECDH_AESGCM.value:      SecurityMode.CLASSICAL.value,
    SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value: SecurityMode.HYBRID.value,
    SecurityProfile.PQC_MLKEM512_AESGCM.value:        SecurityMode.PQC.value,
    SecurityProfile.PQC_MLKEM768_AESGCM.value:        SecurityMode.PQC.value,
    SecurityProfile.PQC_MLKEM1024_AESGCM.value:       SecurityMode.PQC.value,
}

# Minimum Mode per Sensitivity Tier (Informative baseline summary)
TIER_MINIMUM_MODE: Final[dict[str, str]] = {
    SensitivityTier.LOW.value:      SecurityMode.CLASSICAL.value,
    SensitivityTier.MEDIUM.value:   SecurityMode.HYBRID.value,
    SensitivityTier.HIGH.value:     SecurityMode.HYBRID.value,
    SensitivityTier.CRITICAL.value: SecurityMode.PQC.value,
}

# Default Approved Security Profile Sets per Sensitivity Tier
TIER_APPROVED_PROFILES: Final[dict[str, list[str]]] = {
    SensitivityTier.LOW.value: [
        SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
        SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
        SecurityProfile.PQC_MLKEM512_AESGCM.value,
        SecurityProfile.PQC_MLKEM768_AESGCM.value,
    ],
    SensitivityTier.MEDIUM.value: [
        SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
        SecurityProfile.PQC_MLKEM512_AESGCM.value,
        SecurityProfile.PQC_MLKEM768_AESGCM.value,
    ],
    SensitivityTier.HIGH.value: [
        SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
        SecurityProfile.PQC_MLKEM512_AESGCM.value,
        SecurityProfile.PQC_MLKEM768_AESGCM.value,
    ],
    SensitivityTier.CRITICAL.value: [
        SecurityProfile.PQC_MLKEM512_AESGCM.value,
        SecurityProfile.PQC_MLKEM768_AESGCM.value,
        SecurityProfile.PQC_MLKEM1024_AESGCM.value,
    ],
}

# Experimental Baseline Modes
class BaselineMode(str, Enum):
    STATIC_CLASSICAL     = "static_classical"
    STATIC_HYBRID        = "static_hybrid"
    STATIC_PQC           = "static_pqc"
    SENSITIVITY_ONLY     = "sensitivity_only"
    DOWNGRADE_ON_FAILURE = "downgrade_on_failure"
    STATIC_RETRY         = "static_retry_with_floor"
    FULL_GATEWAY         = "full_gateway"

# Blueprint-Aligned Baseline Descriptions
BASELINE_DESCRIPTIONS: Final[dict[str, str]] = {
    BaselineMode.STATIC_CLASSICAL.value: (
        "B1: Static Classical (ECDH). Strictly Classical key exchange; rejects non-classical "
        "requests and rejects flows where policy floor requires Hybrid or PQC."
    ),
    BaselineMode.STATIC_HYBRID.value: (
        "B2: Static Hybrid (X25519 + ML-KEM). Fixed hybrid mode; rejects non-hybrid requests "
        "and rejects flows requiring PQC floor."
    ),
    BaselineMode.STATIC_PQC.value: (
        "B3: Static PQC (ML-KEM). Fixed pure post-quantum mode; rejects non-PQC requests and "
        "fails constrained devices unable to support PQC wire sizes or memory."
    ),
    BaselineMode.SENSITIVITY_ONLY.value: (
        "B4: Sensitivity-Only. Enforces policy floor strictly by sensitivity tier, but disables "
        "all cause-classified recovery adaptations (no MTU fragmentation hints or backoff)."
    ),
    BaselineMode.DOWNGRADE_ON_FAILURE.value: (
        "B5: Downgrade-on-Failure. Naive industry fallback that steps down cryptographic mode "
        "to maintain connectivity upon failure, deliberately violating the security floor."
    ),
    BaselineMode.STATIC_RETRY.value: (
        "B6: Static Retry with Floor. Enforces security floor, but retries blindly without "
        "classifying fault cause or adapting MTU packet size."
    ),
    BaselineMode.FULL_GATEWAY.value: (
        "B7: Full QERIS Gateway. Dynamic signed policy floor, pure deterministic readiness, "
        "S3 cause-classified recovery, adaptive MTU fragmentation, and DEC-4 epoch guards."
    ),
}

# Behavioral Recovery Properties per Baseline
BASELINE_RECOVERY_PROPERTIES: Final[dict[str, dict[str, Any]]] = {
    BaselineMode.STATIC_CLASSICAL.value: {
        "adaptive_recovery": False,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": False,
        "fixed_mode": "CLASSICAL",
    },
    BaselineMode.STATIC_HYBRID.value: {
        "adaptive_recovery": False,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": False,
        "fixed_mode": "HYBRID",
    },
    BaselineMode.STATIC_PQC.value: {
        "adaptive_recovery": False,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": False,
        "fixed_mode": "PQC",
    },
    BaselineMode.SENSITIVITY_ONLY.value: {
        "adaptive_recovery": False,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": False,
        "fixed_mode": None,
    },
    BaselineMode.DOWNGRADE_ON_FAILURE.value: {
        "adaptive_recovery": False,
        "enforces_floor": False,  # Deliberately violates floor for experimental comparator
        "allows_downgrade": True,
        "provides_fragmentation_hints": False,
        "fixed_mode": None,
    },
    BaselineMode.STATIC_RETRY.value: {
        "adaptive_recovery": False,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": False,
        "fixed_mode": None,
    },
    BaselineMode.FULL_GATEWAY.value: {
        "adaptive_recovery": True,
        "enforces_floor": True,
        "allows_downgrade": False,
        "provides_fragmentation_hints": True,
        "fixed_mode": None,
    },
}

# Rate Limiter Defaults
DEFAULT_RATE_LIMIT_CAPACITY: Final[float] = 10.0   # Tokens (burst capacity)
DEFAULT_RATE_LIMIT_REFILL_RATE: Final[float] = 2.0  # Tokens per second (120 req/min)

# Cloud Forwarding Queue Defaults
DEFAULT_CLOUD_QUEUE_MAX_SIZE: Final[int] = 1000
DEFAULT_CLOUD_FORWARD_TIMEOUT_S: Final[float] = 2.0

# Centralized, Frozen Gateway Configuration Model
class GatewayConfig:
    """
    Centralized, frozen configuration for S2 Gateway operations and experimental baselines.
    """
    def __init__(
        self,
        config_version: str = "2.0.0-frozen",
        baseline_mode: BaselineMode = BaselineMode.FULL_GATEWAY,
        sig_alg: str = DEFAULT_SIG_ALG,
        authority_id: str = DEFAULT_AUTHORITY_ID,
        rate_limit_capacity: float = DEFAULT_RATE_LIMIT_CAPACITY,
        rate_limit_refill_rate: float = DEFAULT_RATE_LIMIT_REFILL_RATE,
        rate_limit_enabled: bool = True,
        cloud_queue_max_size: int = DEFAULT_CLOUD_QUEUE_MAX_SIZE,
        cloud_forward_timeout_s: float = DEFAULT_CLOUD_FORWARD_TIMEOUT_S,
        cloud_url: str = DEFAULT_CLOUD_URL,
        cloud_ca_cert: Optional[str] = DEFAULT_CLOUD_CA_CERT,
        admin_api_key: Optional[str] = None,
        policy_db_path: str = DEFAULT_POLICY_DB_PATH,
        registry_db_path: str = DEFAULT_REGISTRY_DB_PATH,
        cloud_db_path: str = DEFAULT_CLOUD_DB_PATH,
        audit_log_path: str = DEFAULT_AUDIT_LOG_PATH,
    ):
        self.config_version = config_version
        self.baseline_mode = baseline_mode if isinstance(baseline_mode, BaselineMode) else BaselineMode(baseline_mode)
        self.sig_alg = sig_alg
        self.authority_id = authority_id
        self.rate_limit_capacity = float(rate_limit_capacity)
        self.rate_limit_refill_rate = float(rate_limit_refill_rate)
        self.rate_limit_enabled = bool(rate_limit_enabled)
        self.cloud_queue_max_size = int(cloud_queue_max_size)
        self.cloud_forward_timeout_s = float(cloud_forward_timeout_s)
        self.cloud_url = cloud_url
        self.cloud_ca_cert = cloud_ca_cert
        self.admin_api_key = admin_api_key if admin_api_key is not None else DEFAULT_ADMIN_API_KEY
        self.policy_db_path = policy_db_path
        self.registry_db_path = registry_db_path
        self.cloud_db_path = cloud_db_path
        self.audit_log_path = audit_log_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_version": self.config_version,
            "baseline_mode": self.baseline_mode.value,
            "sig_alg": self.sig_alg,
            "authority_id": self.authority_id,
            "rate_limit_capacity": self.rate_limit_capacity,
            "rate_limit_refill_rate": self.rate_limit_refill_rate,
            "rate_limit_enabled": self.rate_limit_enabled,
            "cloud_queue_max_size": self.cloud_queue_max_size,
            "cloud_forward_timeout_s": self.cloud_forward_timeout_s,
            "cloud_url": self.cloud_url,
            "cloud_ca_cert": self.cloud_ca_cert,
            "admin_api_key": "[CONFIGURED]" if self.admin_api_key else None,
            "policy_db_path": self.policy_db_path,
            "registry_db_path": self.registry_db_path,
            "cloud_db_path": self.cloud_db_path,
            "audit_log_path": self.audit_log_path,
        }

    def compute_digest(self) -> str:
        """Computes RFC 8785 canonical SHA-256 digest of frozen configuration."""
        import hashlib
        from qeris.s2.canonical_json import canonical_encode
        c_bytes = canonical_encode(self.to_dict())
        return hashlib.sha256(c_bytes).hexdigest()
