"""S3 - Task T16: Replay Protection with Fast-Forward Bound

Protects the signed policy version store against two distinct attacks:
  1. Rollback / Replay  — feeding an old validly-signed policy to re-enable
                          a weaker algorithm or lower security floor. (T11)
  2. Fast-Forward       — feeding an enormous version number to freeze all
                          future legitimate updates (no future version could
                          exceed the recorded highest). (S3 spec §E)

Design (from S3 spec §E and threat model §6.3)
----------------------------------------------
Accept a new policy version only if ALL conditions hold:
  a. The ML-DSA signature is valid and the authority is pinned/trusted.
  b. incoming_version > persisted_highest_version
     (strictly greater — equal version is also rejected to prevent re-delivery
      of the exact same policy being used to reset state.)
  c. incoming_version <= persisted_highest_version + max_version_jump
     (fast-forward bound — prevents a rogue policy from jumping to INT_MAX
      and making every future legitimate version appear "old".)
  d. incoming_version >= min_acceptable_version
     (floor set by the policy's own min_acceptable_version field.)

All failures are classified as SECURITY_FAILURE by the taxonomy and are
forwarded as events to the state machine (which moves to Quarantined on
repeated violations).

Persistence
-----------
The persisted highest version is written atomically to disk.  A restart
cannot erase it.  If the file is corrupt the gateway fails closed and
refuses all policy loads until an administrator intervenes. (Invariant 5)
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ReplayCheckResult(Enum):
    ACCEPTED          = auto()   # version is fresh, in-range, above floor
    REPLAYED          = auto()   # version <= persisted highest (rollback/replay)
    FAST_FORWARD      = auto()   # version jump exceeds max_version_jump
    BELOW_MIN         = auto()   # version < min_acceptable_version
    STORE_ERROR       = auto()   # could not read/write persistent state


@dataclass(frozen=True)
class ReplayCheckOutcome:
    result: ReplayCheckResult
    incoming_version: int
    persisted_version: int
    min_acceptable: int
    max_version_jump: int
    detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.result is ReplayCheckResult.ACCEPTED


# ---------------------------------------------------------------------------
# Persistent version store (replay / fast-forward protection)
# ---------------------------------------------------------------------------

class ReplayProtection:
    """Persistent monotonic version tracker with fast-forward bound.

    Parameters
    ----------
    path:
        File path for the persistent store.  None → in-memory only (tests).
    max_version_jump:
        Maximum allowed difference between incoming version and current
        highest.  Prevents fast-forward freeze attacks.
        Recommended: 10–100 depending on deployment cadence.
    in_memory:
        Force in-memory mode (for tests).
    """

    def __init__(
        self,
        path: Optional[str | Path] = None,
        max_version_jump: int = 50,
        in_memory: bool = False,
    ):
        if max_version_jump < 1:
            raise ValueError("max_version_jump must be >= 1")
        self._path = Path(path) if path else None
        self._in_memory = in_memory or (path is None)
        self._max_jump = max_version_jump
        self._highest: int = 0
        self._min_acceptable: int = 0
        self._loaded: bool = False

    # ------------------------------------------------------------------ public

    def load(self) -> None:
        """Load persisted state from disk.  Must be called once at startup.

        If the file does not exist (first run), starts from zero.
        Corrupt or tampered files raise RuntimeError → gateway fails closed.
        """
        if self._in_memory:
            self._loaded = True
            return
        assert self._path is not None
        hash_path = self._path.with_suffix(".sha256")
        if not self._path.exists():
            self._loaded = True
            return
        try:
            payload = self._path.read_bytes()
            stored_hash = hash_path.read_text(encoding="ascii").strip()
        except OSError as e:
            raise RuntimeError(f"replay_store_read_error:{e}") from e
        if _sha256(payload) != stored_hash:
            raise RuntimeError(
                "replay_store_checksum_mismatch: possible tampering or corruption"
            )
        try:
            data = json.loads(payload)
            self._highest = int(data["highest"])
            self._min_acceptable = int(data["min_acceptable"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
            raise RuntimeError(f"replay_store_malformed:{e}") from e
        self._loaded = True

    def check_and_accept(
        self,
        incoming_version: int,
        min_acceptable_version: int = 0,
    ) -> ReplayCheckOutcome:
        """Validate *incoming_version* and, if accepted, persist it.

        Returns a ReplayCheckOutcome.  The caller must inspect `.accepted`
        before proceeding.  A non-accepted result must be forwarded to the
        state machine as a SecurityFailure event.
        """
        if not self._loaded:
            return ReplayCheckOutcome(
                result=ReplayCheckResult.STORE_ERROR,
                incoming_version=incoming_version,
                persisted_version=self._highest,
                min_acceptable=self._min_acceptable,
                max_version_jump=self._max_jump,
                detail="store_not_loaded:call_load_first",
            )

        effective_min = max(self._min_acceptable, min_acceptable_version)

        # Rule (d): min_acceptable floor
        if incoming_version < effective_min:
            return ReplayCheckOutcome(
                result=ReplayCheckResult.BELOW_MIN,
                incoming_version=incoming_version,
                persisted_version=self._highest,
                min_acceptable=effective_min,
                max_version_jump=self._max_jump,
                detail=(
                    f"incoming={incoming_version} < "
                    f"min_acceptable={effective_min}"
                ),
            )

        # Rule (b): strictly greater than persisted highest
        if incoming_version <= self._highest:
            return ReplayCheckOutcome(
                result=ReplayCheckResult.REPLAYED,
                incoming_version=incoming_version,
                persisted_version=self._highest,
                min_acceptable=effective_min,
                max_version_jump=self._max_jump,
                detail=(
                    f"incoming={incoming_version} <= "
                    f"persisted={self._highest} — replay/rollback"
                ),
            )

        # Rule (c): fast-forward bound
        if incoming_version > self._highest + self._max_jump:
            return ReplayCheckOutcome(
                result=ReplayCheckResult.FAST_FORWARD,
                incoming_version=incoming_version,
                persisted_version=self._highest,
                min_acceptable=effective_min,
                max_version_jump=self._max_jump,
                detail=(
                    f"incoming={incoming_version} > "
                    f"persisted={self._highest} + jump={self._max_jump} — "
                    f"fast-forward freeze attempt"
                ),
            )

        # All rules passed — accept and persist.
        new_min = max(self._min_acceptable, min_acceptable_version)
        self._persist(incoming_version, new_min)
        self._highest = incoming_version
        self._min_acceptable = new_min

        return ReplayCheckOutcome(
            result=ReplayCheckResult.ACCEPTED,
            incoming_version=incoming_version,
            persisted_version=incoming_version,
            min_acceptable=new_min,
            max_version_jump=self._max_jump,
        )

    @property
    def highest_version(self) -> int:
        return self._highest

    @property
    def min_acceptable_version(self) -> int:
        return self._min_acceptable

    # ----------------------------------------------------------------- private

    def _persist(self, highest: int, min_acceptable: int) -> None:
        if self._in_memory:
            return
        assert self._path is not None
        payload = json.dumps(
            {"highest": highest, "min_acceptable": min_acceptable},
            separators=(",", ":"),
        ).encode("utf-8")
        digest = _sha256(payload)
        # Atomic rename write
        dir_ = self._path.parent
        try:
            fd, tmp = tempfile.mkstemp(dir=str(dir_), suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception:
                os.unlink(tmp)
                raise
            os.replace(tmp, str(self._path))
        except OSError as e:
            raise RuntimeError(f"replay_store_write_error:{e}") from e
        self._path.with_suffix(".sha256").write_text(digest + "\n", encoding="ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
