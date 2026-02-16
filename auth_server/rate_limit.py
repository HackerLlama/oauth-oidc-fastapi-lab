"""
Rate limiting (M14). In-memory sliding window per key (e.g. per IP).
Used for POST /authorize (login) and POST /token to mitigate brute force and abuse.
"""
import math
import threading
import time

_store: dict[str, list[float]] = {}
_lock = threading.Lock()
_WINDOW_SECONDS = 60


def check_and_consume(
    key: str,
    limit: int,
    window_seconds: int = _WINDOW_SECONDS,
) -> tuple[bool, int | None]:
    """
    Check if the key is under the limit for the sliding window; if so, record this request.
    Returns (allowed, retry_after_seconds). When not allowed, retry_after_seconds is the
    suggested Retry-After value (>= 1).
    """
    if limit <= 0:
        return True, None
    now = time.monotonic()
    with _lock:
        if key not in _store:
            _store[key] = []
        timestamps = _store[key]
        cutoff = now - window_seconds
        timestamps[:] = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= limit:
            oldest = min(timestamps) if timestamps else now
            retry_after = max(1, math.ceil(window_seconds - (now - oldest)))
            return False, retry_after
        timestamps.append(now)
        return True, None
