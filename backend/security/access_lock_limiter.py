import time
import threading
from typing import Dict, Tuple

class AccessLockLimiter:
    """
    In-memory rate limiter for document access lock key attempts.
    Blocks repeated failed unlock attempts to prevent brute-forcing document keys.
    Thread-safe and memory-bounded.
    """
    def __init__(self, max_attempts: int = 5, lock_duration_sec: int = 900):
        self.max_attempts = max_attempts
        self.lock_duration_sec = lock_duration_sec
        self._lock = threading.Lock()
        self._attempts: Dict[Tuple[int, int, str], Tuple[int, float]] = {}  # (doc_id, user_id, ip) -> (count, first_attempt_time)
        self._lockouts: Dict[Tuple[int, int, str], float] = {}  # (doc_id, user_id, ip) -> lockout_until_timestamp

    def _cleanup_expired(self, now: float):
        """Remove old records beyond lock duration."""
        expired_keys = [k for k, until in self._lockouts.items() if now > until]
        for k in expired_keys:
            del self._lockouts[k]

        expired_attempts = [
            k for k, (count, start) in self._attempts.items()
            if now - start > self.lock_duration_sec
        ]
        for k in expired_attempts:
            del self._attempts[k]

    def is_blocked(self, doc_id: int, user_id: int, ip_address: str) -> Tuple[bool, int]:
        now = time.time()
        key = (doc_id, user_id, ip_address or "unknown")
        with self._lock:
            self._cleanup_expired(now)
            if key in self._lockouts:
                until = self._lockouts[key]
                if now < until:
                    remaining_sec = int(until - now)
                    return True, remaining_sec
                else:
                    del self._lockouts[key]
            return False, 0

    def record_failure(self, doc_id: int, user_id: int, ip_address: str) -> Tuple[int, bool]:
        """
        Record failed key entry. Returns (attempts_so_far, threshold_exceeded_just_now).
        """
        now = time.time()
        key = (doc_id, user_id, ip_address or "unknown")
        with self._lock:
            self._cleanup_expired(now)
            count, start = self._attempts.get(key, (0, now))
            count += 1
            threshold_exceeded = False

            if count >= self.max_attempts:
                self._lockouts[key] = now + self.lock_duration_sec
                self._attempts.pop(key, None)
                threshold_exceeded = True
            else:
                self._attempts[key] = (count, start)

            return count, threshold_exceeded

    def record_success(self, doc_id: int, user_id: int, ip_address: str):
        """Clear failed attempt counters on successful unlock."""
        key = (doc_id, user_id, ip_address or "unknown")
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)

    def reset_all_for_tests(self):
        with self._lock:
            self._attempts.clear()
            self._lockouts.clear()


# Singleton instance
access_lock_limiter = AccessLockLimiter()
