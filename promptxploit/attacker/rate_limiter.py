# attacker/rate_limiter.py
# Simple rate limiter to pace attacks against a target endpoint.
# e.g. RateLimiter(max_per_minute=5) -> at most 5 attacks per minute.

import time


class RateLimiter:
    """Evenly spaces calls so no more than `max_per_minute` happen per minute.

    max_per_minute <= 0 means unlimited (no pacing). Call .wait() immediately
    before each attack; the first call never blocks.
    """

    def __init__(self, max_per_minute: float = 0):
        self.max_per_minute = max_per_minute
        self.interval = 60.0 / max_per_minute if max_per_minute and max_per_minute > 0 else 0.0
        self._last = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        now = time.monotonic()
        if self._last:
            remaining = self.interval - (now - self._last)
            if remaining > 0:
                time.sleep(remaining)
        self._last = time.monotonic()
