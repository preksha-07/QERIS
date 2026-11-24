"""
QERIS S2: Device Capability Registry

Implements persistent tracking of gateway-registered device capabilities.
Capabilities are registered by the gateway/administrator and are NOT hardware-attested.
Device-reported claims never override or relax registered capabilities.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from qeris.s2.config import (
    DEFAULT_REGISTRY_DB_PATH,
    SecurityMode,
    SecurityProfile,
)


@dataclass
class DeviceCapabilityProfile:
    device_id: str
    device_class: str = "esp32_constrained"  # esp32_constrained, edge_gateway, standard_compute
    supported_modes: list[str] = field(default_factory=lambda: ["CLASSICAL", "HYBRID", "PQC"])
    supported_security_profiles: list[str] = field(
        default_factory=lambda: [
            SecurityProfile.CLASSICAL_ECDH_AESGCM.value,
            SecurityProfile.HYBRID_X25519_MLKEM_AESGCM.value,
            SecurityProfile.PQC_MLKEM512_AESGCM.value,
        ]
    )
    ml_kem_capable: bool = True
    ml_dsa_capable: bool = False
    memory_class: str = "LOW_RAM_320KB"  # LOW_RAM_320KB, MEDIUM_RAM_1MB, HIGH_RAM_1GB
    ram_bytes_available: int = 320 * 1024
    max_packet_size_mtu: int = 1280
    firmware_version: str = "v1.0.0"
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    last_seen: Optional[float] = None
    recent_results: list[dict[str, Any]] = field(default_factory=list)
    migration_status: str = "MIGRATING"  # LEGACY, MIGRATING, PQC_READY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceCapabilityProfile:
        return cls(
            device_id=data["device_id"],
            device_class=data.get("device_class", "esp32_constrained"),
            supported_modes=list(data.get("supported_modes", ["CLASSICAL"])),
            supported_security_profiles=list(data.get("supported_security_profiles", [])),
            ml_kem_capable=bool(data.get("ml_kem_capable", False)),
            ml_dsa_capable=bool(data.get("ml_dsa_capable", False)),
            memory_class=data.get("memory_class", "LOW_RAM_320KB"),
            ram_bytes_available=int(data.get("ram_bytes_available", 320 * 1024)),
            max_packet_size_mtu=int(data.get("max_packet_size_mtu", 1280)),
            firmware_version=data.get("firmware_version", "v1.0.0"),
            quarantined=bool(data.get("quarantined", False)),
            quarantine_reason=data.get("quarantine_reason"),
            last_seen=data.get("last_seen"),
            recent_results=list(data.get("recent_results", [])),
            migration_status=data.get("migration_status", "MIGRATING"),
        )


class DeviceRegistry:
    """
    Persistent SQLite storage for gateway-registered device capability profiles.
    """

    def __init__(self, db_path: str = DEFAULT_REGISTRY_DB_PATH):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_capabilities (
                    device_id TEXT PRIMARY KEY,
                    device_class TEXT NOT NULL,
                    supported_modes TEXT NOT NULL,
                    supported_profiles TEXT NOT NULL,
                    ml_kem_capable INTEGER NOT NULL,
                    ml_dsa_capable INTEGER NOT NULL,
                    memory_class TEXT NOT NULL,
                    ram_bytes_available INTEGER NOT NULL,
                    max_packet_size_mtu INTEGER NOT NULL,
                    firmware_version TEXT NOT NULL,
                    quarantined INTEGER NOT NULL,
                    quarantine_reason TEXT,
                    last_seen REAL,
                    recent_results TEXT NOT NULL,
                    migration_status TEXT NOT NULL,
                    registered_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

    def register_device(self, profile: DeviceCapabilityProfile) -> None:
        """Enrolls or updates a device capability profile in the persistent registry."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO device_capabilities (
                    device_id, device_class, supported_modes, supported_profiles,
                    ml_kem_capable, ml_dsa_capable, memory_class, ram_bytes_available,
                    max_packet_size_mtu, firmware_version, quarantined, quarantine_reason,
                    last_seen, recent_results, migration_status, registered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_class = excluded.device_class,
                    supported_modes = excluded.supported_modes,
                    supported_profiles = excluded.supported_profiles,
                    ml_kem_capable = excluded.ml_kem_capable,
                    ml_dsa_capable = excluded.ml_dsa_capable,
                    memory_class = excluded.memory_class,
                    ram_bytes_available = excluded.ram_bytes_available,
                    max_packet_size_mtu = excluded.max_packet_size_mtu,
                    firmware_version = excluded.firmware_version,
                    quarantined = excluded.quarantined,
                    quarantine_reason = excluded.quarantine_reason,
                    migration_status = excluded.migration_status,
                    updated_at = excluded.updated_at
                """,
                (
                    profile.device_id,
                    profile.device_class,
                    json.dumps(profile.supported_modes),
                    json.dumps(profile.supported_security_profiles),
                    1 if profile.ml_kem_capable else 0,
                    1 if profile.ml_dsa_capable else 0,
                    profile.memory_class,
                    profile.ram_bytes_available,
                    profile.max_packet_size_mtu,
                    profile.firmware_version,
                    1 if profile.quarantined else 0,
                    profile.quarantine_reason,
                    profile.last_seen,
                    json.dumps(profile.recent_results[-20:]),  # Keep last 20 results
                    profile.migration_status,
                    now,
                    now,
                ),
            )

    def get_device(self, device_id: str) -> Optional[DeviceCapabilityProfile]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM device_capabilities WHERE device_id = ?",
                (device_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return DeviceCapabilityProfile(
                device_id=row["device_id"],
                device_class=row["device_class"],
                supported_modes=json.loads(row["supported_modes"]),
                supported_security_profiles=json.loads(row["supported_profiles"]),
                ml_kem_capable=bool(row["ml_kem_capable"]),
                ml_dsa_capable=bool(row["ml_dsa_capable"]),
                memory_class=row["memory_class"],
                ram_bytes_available=int(row["ram_bytes_available"]),
                max_packet_size_mtu=int(row["max_packet_size_mtu"]),
                firmware_version=row["firmware_version"],
                quarantined=bool(row["quarantined"]),
                quarantine_reason=row["quarantine_reason"],
                last_seen=row["last_seen"],
                recent_results=json.loads(row["recent_results"]),
                migration_status=row["migration_status"],
            )

    def list_devices(self) -> list[DeviceCapabilityProfile]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM device_capabilities ORDER BY device_id ASC")
            return [
                DeviceCapabilityProfile(
                    device_id=row["device_id"],
                    device_class=row["device_class"],
                    supported_modes=json.loads(row["supported_modes"]),
                    supported_security_profiles=json.loads(row["supported_profiles"]),
                    ml_kem_capable=bool(row["ml_kem_capable"]),
                    ml_dsa_capable=bool(row["ml_dsa_capable"]),
                    memory_class=row["memory_class"],
                    ram_bytes_available=int(row["ram_bytes_available"]),
                    max_packet_size_mtu=int(row["max_packet_size_mtu"]),
                    firmware_version=row["firmware_version"],
                    quarantined=bool(row["quarantined"]),
                    quarantine_reason=row["quarantine_reason"],
                    last_seen=row["last_seen"],
                    recent_results=json.loads(row["recent_results"]),
                    migration_status=row["migration_status"],
                )
                for row in cursor.fetchall()
            ]

    def set_quarantine(self, device_id: str, quarantined: bool, reason: Optional[str] = None) -> bool:
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE device_capabilities
                SET quarantined = ?, quarantine_reason = ?, updated_at = ?
                WHERE device_id = ?
                """,
                (1 if quarantined else 0, reason, now, device_id),
            )
            return cursor.rowcount > 0

    def record_recent_result(self, device_id: str, result: dict[str, Any]) -> None:
        device = self.get_device(device_id)
        if not device:
            return
        results = device.recent_results
        results.append(result)
        results = results[-20:]
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE device_capabilities
                SET recent_results = ?, last_seen = ?, updated_at = ?
                WHERE device_id = ?
                """,
                (json.dumps(results), now, now, device_id),
            )
