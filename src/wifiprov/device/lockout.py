"""Slowing down anyone who keeps guessing the setup code."""

from __future__ import annotations

import math
import time
from collections.abc import Callable

Clock = Callable[[], float]


class Lockout:
    """Refuses new attempts for a while after too many wrong guesses in a row.

    The setup code has 40 bits, which is plenty against online guessing only if
    the device stops answering after a few wrong tries. A correct code resets the
    count. The clock is a parameter so tests can move time by hand.

    The count lives in memory, so it starts again when the device restarts.
    Anyone who can restart the device is next to it, and that is the situation
    the physical button in a real product is meant to cover.
    """

    def __init__(
        self, *, max_failures: int = 5, duration: float = 300.0, clock: Clock = time.monotonic
    ) -> None:
        if max_failures < 1 or duration <= 0:
            raise ValueError("a lockout needs at least one failure and a positive duration")
        self._max_failures = max_failures
        self._duration = duration
        self._clock = clock
        self._failures = 0
        self._locked_until: float | None = None

    def is_locked(self) -> bool:
        self._expire()
        return self._locked_until is not None

    def retry_after(self) -> int:
        """Whole seconds until attempts are allowed again, rounded up. 0 if not locked."""
        self._expire()
        if self._locked_until is None:
            return 0
        return math.ceil(self._locked_until - self._clock())

    def record_failure(self) -> None:
        self._expire()
        if self._locked_until is not None:
            return
        self._failures += 1
        if self._failures >= self._max_failures:
            self._locked_until = self._clock() + self._duration

    def record_success(self) -> None:
        self._failures = 0

    def _expire(self) -> None:
        if self._locked_until is not None and self._clock() >= self._locked_until:
            self._locked_until = None
            self._failures = 0
