"""
QERIS S2: Gateway-to-Cloud Forwarding Client and Bounded Outage Queue

Handles real data transfer from the trusted gateway to the cloud service.
Enforces bounded cloud-outage behavior:
1. When cloud is online: immediately delivers telemetry via HTTP.
2. When cloud is offline/unavailable: buffers messages in a bounded FIFO queue.
3. When queue is full: safely drops oldest/newest with explicit DROP status.
4. Never falsely reports successful cloud delivery if cloud has not received it.
"""
from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import httpx

from qeris.s2.config import (
    DEFAULT_CLOUD_CA_CERT,
    DEFAULT_CLOUD_FORWARD_TIMEOUT_S,
    DEFAULT_CLOUD_QUEUE_MAX_SIZE,
    DEFAULT_CLOUD_URL,
)


class CloudForwardStatus(str, Enum):
    FORWARDED_TO_CLOUD       = "FORWARDED_TO_CLOUD"
    QUEUED_FOR_CLOUD         = "QUEUED_FOR_CLOUD"
    CLOUD_DROPPED_QUEUE_FULL = "CLOUD_DROPPED_QUEUE_FULL"
    CLOUD_FORWARDING_FAILED  = "CLOUD_FORWARDING_FAILED"


@dataclass
class CloudForwardResult:
    status: CloudForwardStatus
    delivered: bool
    event_id: str
    detail: str
    queue_size: int = 0


class CloudForwardingClient:
    """
    Client used by the gateway to forward accepted telemetry to the cloud service.
    Features a bounded FIFO queue for handling temporary cloud outages.
    """

    def __init__(
        self,
        cloud_url: str = DEFAULT_CLOUD_URL,
        max_queue_size: int = DEFAULT_CLOUD_QUEUE_MAX_SIZE,
        timeout_seconds: float = DEFAULT_CLOUD_FORWARD_TIMEOUT_S,
        ca_cert_path: Optional[str] = DEFAULT_CLOUD_CA_CERT,
        mock_cloud_handler: Optional[Any] = None,
    ):
        self.cloud_url = cloud_url.rstrip("/")
        self.max_queue_size = max_queue_size
        self.timeout_seconds = timeout_seconds
        self.ca_cert_path = ca_cert_path
        self._mock_cloud_handler = mock_cloud_handler  # In-process mock or test client

        self._queue: collections.deque[dict[str, Any]] = collections.deque(maxlen=max_queue_size)
        self._lock = threading.Lock()
        self._dropped_count: int = 0

    @property
    def queue_size(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_count

    def clear(self) -> None:
        """Clears the outage queue and resets dropped count for experiment isolation."""
        with self._lock:
            self._queue.clear()
            self._dropped_count = 0

    def forward_telemetry(self, message: dict[str, Any]) -> CloudForwardResult:
        """
        Attempts immediate delivery to the cloud service.
        If cloud is unreachable, enqueues the message up to max_queue_size.
        """
        event_id = message.get("event_id", "unknown")

        # First, attempt to flush any previously queued messages
        self._flush_queue_internal()

        # Attempt immediate delivery
        delivered, detail = self._send_to_cloud(message)
        if delivered:
            return CloudForwardResult(
                status=CloudForwardStatus.FORWARDED_TO_CLOUD,
                delivered=True,
                event_id=event_id,
                detail=detail,
                queue_size=len(self._queue),
            )

        # Cloud is unavailable -> enqueue message
        with self._lock:
            if len(self._queue) >= self.max_queue_size:
                self._dropped_count += 1
                return CloudForwardResult(
                    status=CloudForwardStatus.CLOUD_DROPPED_QUEUE_FULL,
                    delivered=False,
                    event_id=event_id,
                    detail=f"Cloud unavailable ({detail}) and buffer queue is full ({self.max_queue_size} items); message dropped",
                    queue_size=len(self._queue),
                )

            self._queue.append(message)
            q_len = len(self._queue)

        return CloudForwardResult(
            status=CloudForwardStatus.QUEUED_FOR_CLOUD,
            delivered=False,
            event_id=event_id,
            detail=f"Cloud unavailable ({detail}); telemetry buffered in local queue ({q_len}/{self.max_queue_size})",
            queue_size=q_len,
        )

    def flush_queue(self) -> int:
        """Flushes all queued items to cloud. Returns count of successfully forwarded items."""
        return self._flush_queue_internal()

    def _flush_queue_internal(self) -> int:
        with self._lock:
            if not self._queue:
                return 0
            pending = list(self._queue)
            self._queue.clear()

        forwarded_count = 0
        still_pending = []

        for msg in pending:
            ok, _ = self._send_to_cloud(msg)
            if ok:
                forwarded_count += 1
            else:
                # Cloud is still offline
                still_pending.append(msg)

        if still_pending:
            with self._lock:
                # Re-insert still pending items at front of queue
                still_pending.extend(self._queue)
                self._queue.clear()
                for item in still_pending[:self.max_queue_size]:
                    self._queue.append(item)

        return forwarded_count

    def _send_to_cloud(self, message: dict[str, Any]) -> tuple[bool, str]:
        """Internal helper to dispatch HTTP POST to cloud API."""
        if self._mock_cloud_handler is not None:
            # Custom in-process test handler
            try:
                res = self._mock_cloud_handler(message)
                if res.get("status") in ("STORED", "OK", 201, 200):
                    return True, "Delivered via in-process handler"
                return False, res.get("detail", "Mock handler rejected")
            except Exception as exc:
                return False, f"Mock handler failed: {exc}"

        endpoint = f"{self.cloud_url}/api/v1/cloud/ingest"
        try:
            # Enforce genuine TLS certificate verification
            verify_opt: Any = True
            if self.cloud_url.startswith("https://"):
                if self.ca_cert_path:
                    import ssl
                    from pathlib import Path
                    if Path(self.ca_cert_path).exists():
                        verify_opt = ssl.create_default_context(cafile=str(self.ca_cert_path))
                    else:
                        verify_opt = self.ca_cert_path
                else:
                    verify_opt = True  # Strict verification via system/default trust store
            with httpx.Client(timeout=self.timeout_seconds, verify=verify_opt, trust_env=False) as client:
                resp = client.post(endpoint, json=message)
                if resp.status_code in (200, 201):
                    return True, f"HTTP {resp.status_code} OK"
                return False, f"Cloud returned HTTP {resp.status_code}: {resp.text}"
        except httpx.RequestError as exc:
            return False, f"Connection failed: {exc}"
        except Exception as exc:
            return False, f"Unexpected error: {exc}"
