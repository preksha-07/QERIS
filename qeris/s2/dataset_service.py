"""
QERIS Dataset Service: Ingestion, Replay, and Tampering Injection Engine.

Provides dataset-backed telemetry using the verified dataset:
- qeris_combined_cleaned_iot_dataset.csv

Mapping of three registered devices to dataset devices:
- device_001 <-> ESP32_NODE_01
- device_002 <-> ESP32_NODE_02
- device_003 <-> ESP32_NODE_03
"""
from __future__ import annotations

import csv
import json
import logging
import os
from pathlib import Path
import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("qeris.dataset_service")

# Mapping contracts
QERIS_TO_DATASET_DEVICE: dict[str, str] = {
    "device_001": "ESP32_NODE_01",
    "device_002": "ESP32_NODE_02",
    "device_003": "ESP32_NODE_03",
}

DATASET_TO_QERIS_DEVICE: dict[str, str] = {
    v: k for k, v in QERIS_TO_DATASET_DEVICE.items()
}

# Permitted categories per device
DEVICE_CATEGORIES: dict[str, set[str]] = {
    "ESP32_NODE_01": {"Environmental_Sensor", "Network_IIoT_Security"},
    "ESP32_NODE_02": {"Environmental_Sensor", "Network_IIoT_Security", "Network_Traffic_Zeek"},
    "ESP32_NODE_03": {"Environmental_Sensor", "Network_IIoT_Security"},
}


class DatasetService:
    """Manages loaded dataset records and background telemetry replay."""

    def __init__(self, csv_path: Optional[Path | str] = None):
        self._lock = threading.Lock()
        self.csv_path = self._locate_csv(csv_path)
        
        # Indexed records: qeris_device_id -> list of record dicts
        self.records_by_device: dict[str, list[dict[str, Any]]] = {
            "device_001": [],
            "device_002": [],
            "device_003": [],
        }
        # Indexed records: (qeris_device_id, flow_id) -> list of record dicts
        self.records_by_device_flow: dict[tuple[str, str], list[dict[str, Any]]] = {}
        
        # Provenance index: record_id -> record dict (subset or on-demand)
        self.record_by_id: dict[str, dict[str, Any]] = {}
        self.total_records_loaded = 0

        # Background replay control
        self._replay_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.replay_interval_sec = 4.0
        self.replay_count = 0
        self.last_replay_record: Optional[dict[str, Any]] = None

        if self.csv_path and self.csv_path.exists():
            self._load_dataset()

    def _locate_csv(self, explicit_path: Optional[Path | str]) -> Optional[Path]:
        """Locates the cleaned dataset CSV in data/ or Downloads."""
        if explicit_path:
            p = Path(explicit_path)
            if p.exists():
                return p

        # Check repository data folder
        repo_data = Path(__file__).resolve().parent.parent.parent / "data" / "qeris_combined_cleaned_iot_dataset.csv"
        if repo_data.exists():
            return repo_data

        # Check user downloads
        user_dl = Path.home() / "Downloads" / "qeris_combined_cleaned_iot_dataset.csv"
        if user_dl.exists():
            return user_dl

        return None

    def _load_dataset(self) -> None:
        """Parses CSV and indexes records strictly for the three mapped devices."""
        if not self.csv_path or not self.csv_path.exists():
            logger.warning("Dataset CSV not found at %s", self.csv_path)
            return

        t0 = time.time()
        loaded = 0

        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ds_dev = row.get("device_id", "").strip()
                qeris_dev = DATASET_TO_QERIS_DEVICE.get(ds_dev)
                if not qeris_dev:
                    continue  # Only load records for the three mapped devices

                flow_id = row.get("flow_id", "").strip()
                cat = row.get("data_category", "").strip()

                # Validate category belongs to this device
                allowed_cats = DEVICE_CATEGORIES.get(ds_dev, set())
                if cat not in allowed_cats:
                    continue

                rec: dict[str, Any] = {
                    "record_id": row.get("record_id", ""),
                    "timestamp": row.get("timestamp", ""),
                    "device_id": qeris_dev,
                    "dataset_device_id": ds_dev,
                    "flow_id": flow_id,
                    "metric_name": row.get("metric_name", ""),
                    "value": row.get("value", ""),
                    "unit": row.get("unit", ""),
                    "sensitivity_tier": row.get("sensitivity_tier", "LOW"),
                    "signed_security_floor": row.get("signed_security_floor", "CLASSICAL"),
                    "requested_mode": row.get("requested_mode", "CLASSICAL"),
                    "is_anomaly": int(row.get("is_anomaly", 0)),
                    "dataset_source": row.get("dataset_source", ""),
                    "data_category": cat,
                    "device_or_mote_id": row.get("device_or_mote_id", ""),
                    "source_ip": row.get("source_ip", ""),
                    "dest_ip": row.get("dest_ip", ""),
                    "connection_or_sensor_status": row.get("connection_or_sensor_status", "ONLINE"),
                    "attack_or_event_type": row.get("attack_or_event_type", "Normal_Sensor_Reading"),
                }

                self.records_by_device[qeris_dev].append(rec)
                key = (qeris_dev, flow_id)
                if key not in self.records_by_device_flow:
                    self.records_by_device_flow[key] = []
                self.records_by_device_flow[key].append(rec)

                # Keep a sample of IDs for direct lookup
                if len(self.record_by_id) < 50000:
                    self.record_by_id[rec["record_id"]] = rec

                loaded += 1

        self.total_records_loaded = loaded
        elapsed = time.time() - t0
        logger.info(
            "DatasetService loaded %d verified records across 3 devices in %.2fs",
            loaded,
            elapsed,
        )

    def get_random_record(
        self,
        device_id: str,
        flow_id: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Randomly selects an existing record from the matching subset."""
        device_id = device_id.strip()
        if device_id not in self.records_by_device:
            return None

        if flow_id:
            flow_id = flow_id.strip()
            key = (device_id, flow_id)
            candidates = self.records_by_device_flow.get(key, [])
        else:
            candidates = self.records_by_device.get(device_id, [])

        if not candidates:
            # Fallback to device pool if specific flow has no records for device
            candidates = self.records_by_device.get(device_id, [])

        if not candidates:
            return None

        # Return a copy of a real record
        return dict(random.choice(candidates))

    @staticmethod
    def format_message(record: dict[str, Any]) -> str:
        """Formats original record fields into an unambiguous message string."""
        return (
            f"[{record['record_id']}] {record['metric_name']}={record['value']} {record['unit']} "
            f"| src={record['dataset_source']} | cat={record['data_category']} | ts={record['timestamp']}"
        )

    def start_background_replay(self, gateway_fn: Any, interval_sec: float = 4.0) -> None:
        """Starts periodic background replay feeding real records into the gateway."""
        with self._lock:
            if self._replay_thread and self._replay_thread.is_alive():
                return
            self._stop_event.clear()
            self.replay_interval_sec = interval_sec
            self._replay_thread = threading.Thread(
                target=self._replay_loop,
                args=(gateway_fn,),
                daemon=True,
                name="QERIS-DatasetReplay",
            )
            self._replay_thread.start()

    def stop_background_replay(self) -> None:
        """Stops the background replay worker."""
        with self._lock:
            self._stop_event.set()
            if self._replay_thread and self._replay_thread.is_alive():
                self._replay_thread.join(timeout=1.0)
            self._replay_thread = None

    def is_replay_running(self) -> bool:
        """Returns True if background replay is active."""
        return self._replay_thread is not None and self._replay_thread.is_alive()

    def replay_tick(self, gateway_fn: Any) -> Optional[dict[str, Any]]:
        """Executes a single replay step using a randomly selected real record."""
        # Pick one of the three mapped devices
        devices = ["device_001", "device_002", "device_003"]
        dev_id = random.choice(devices)
        rec = self.get_random_record(dev_id)
        if not rec:
            return None

        # Submit to gateway
        try:
            result = gateway_fn(rec)
            with self._lock:
                self.replay_count += 1
                self.last_replay_record = {
                    "record_id": rec["record_id"],
                    "device_id": dev_id,
                    "flow_id": rec["flow_id"],
                    "metric_name": rec["metric_name"],
                    "value": rec["value"],
                    "is_anomaly": rec["is_anomaly"],
                    "result": result,
                    "timestamp": time.time(),
                }
            return self.last_replay_record
        except Exception as err:
            logger.error("Dataset replay tick failed: %s", err)
            return None

    def _replay_loop(self, gateway_fn: Any) -> None:
        """Loop running in background thread."""
        while not self._stop_event.is_set():
            self.replay_tick(gateway_fn)
            self._stop_event.wait(self.replay_interval_sec)
