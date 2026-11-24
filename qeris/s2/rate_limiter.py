"""
QERIS S2: Per-Device Rate Limiter

Implements a deterministic token-bucket rate limiter per device ID.
Protects gateway against flood attacks without creating a security downgrade path.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from qeris.s2.config import (
    DEFAULT_RATE_LIMIT_CAPACITY,
    DEFAULT_RATE_LIMIT_REFILL_RATE,
)


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float
    last_update: float

    def consume(self, now: float, tokens_to_consume: float = 1.0) -> tuple[bool, float, float]:
        # Refill tokens based on elapsed time
        elapsed = max(0.0, now - self.last_update)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

        if self.tokens >= tokens_to_consume:
            self.tokens -= tokens_to_consume
            return True, self.tokens, 0.0

        # Not enough tokens
        missing = tokens_to_consume - self.tokens
        retry_after = missing / self.refill_rate if self.refill_rate > 0 else 1.0
        return False, self.tokens, retry_after


class DeviceRateLimiter:
    """
    Thread-safe per-device token bucket rate limiter.
    """

    def __init__(
        self,
        capacity: float = DEFAULT_RATE_LIMIT_CAPACITY,
        refill_rate: float = DEFAULT_RATE_LIMIT_REFILL_RATE,
    ):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check_rate_limit(
        self,
        device_id: str,
        now: Optional[float] = None,
        cost: float = 1.0,
    ) -> tuple[bool, float, float]:
        """
        Consumes tokens for the device.
        Returns:
            (is_allowed: bool, remaining_tokens: float, retry_after_seconds: float)
        """
        current_time = now if now is not None else time.time()
        with self._lock:
            bucket = self._buckets.get(device_id)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=self.capacity,
                    refill_rate=self.refill_rate,
                    tokens=self.capacity,
                    last_update=current_time,
                )
                self._buckets[device_id] = bucket

            return bucket.consume(current_time, cost)

    def reset_device(self, device_id: str) -> None:
        with self._lock:
            self._buckets.pop(device_id, None)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()
