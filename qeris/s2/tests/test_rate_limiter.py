"""
Unit Tests for Per-Device Token Bucket Rate Limiter
"""
import time
import pytest
from qeris.s2.rate_limiter import DeviceRateLimiter

def test_rate_limiter_burst_and_exhaustion():
    # Capacity = 3 tokens, refill = 1 token/sec
    limiter = DeviceRateLimiter(capacity=3.0, refill_rate=1.0)
    dev_id = "test_dev_flood"
    t0 = 1000.0

    # First 3 requests must succeed immediately
    ok1, rem1, _ = limiter.check_rate_limit(dev_id, now=t0)
    ok2, rem2, _ = limiter.check_rate_limit(dev_id, now=t0)
    ok3, rem3, _ = limiter.check_rate_limit(dev_id, now=t0)
    assert ok1 and ok2 and ok3
    assert rem3 < 0.1

    # 4th request at the same time must be rejected
    ok4, rem4, retry_after = limiter.check_rate_limit(dev_id, now=t0)
    assert ok4 is False
    assert retry_after > 0.0

    # After 1.5 seconds, 1 token is refilled
    ok5, rem5, _ = limiter.check_rate_limit(dev_id, now=t0 + 1.5)
    assert ok5 is True

def test_rate_limiter_per_device_isolation():
    limiter = DeviceRateLimiter(capacity=2.0, refill_rate=0.5)
    t0 = 1000.0

    # Exhaust dev_A
    limiter.check_rate_limit("dev_A", now=t0)
    limiter.check_rate_limit("dev_A", now=t0)
    ok_a, _, _ = limiter.check_rate_limit("dev_A", now=t0)
    assert ok_a is False

    # dev_B must NOT be affected by dev_A's exhaustion
    ok_b1, _, _ = limiter.check_rate_limit("dev_B", now=t0)
    ok_b2, _, _ = limiter.check_rate_limit("dev_B", now=t0)
    assert ok_b1 is True
    assert ok_b2 is True
