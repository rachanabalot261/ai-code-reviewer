from __future__ import annotations
import threading
import time


class GeminiThrottle:
    """
    Process-wide pacing for Gemini calls. Free-tier quota is per-project,
    not per-caller, so gemini_reviewer.py and adjudicator.py must share
    ONE instance of this — otherwise each file paces itself independently
    and you still blow the combined RPM ceiling.

    min_interval is conservative on purpose: published free-tier RPM
    numbers for 2.5-flash vary by source (10-15 RPM) and Google has cut
    quotas with no notice before. Check your actual project limit in
    AI Studio's quota page rather than trusting any single number.
    7s between calls = ~8.5 RPM, comfortably under every figure I've seen.
    Tighten it once you've confirmed your real ceiling.
    """

    def __init__(self, min_interval: float = 7.0):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_call = time.time()


# Singleton — import THIS instance everywhere, never instantiate a second one.
throttle = GeminiThrottle(min_interval=7.0)