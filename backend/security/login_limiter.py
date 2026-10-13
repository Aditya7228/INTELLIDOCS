"""
IntelliDocs – Application-level login rate limiter.

Tracks failure attempts per (username_lower, IP) pair and per-IP independently
to prevent single-IP account lockout attacks against legitimate users.

Includes bounded cleanup and LRU/FIFO eviction of expired entries to prevent
unbounded memory growth under automated random-key attacks.

Designed with a clean class wrapper so it can be swapped for a Redis-backed limiter
in multi-worker distributed environments.
"""

import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional
from backend.config import settings

@dataclass
class LockStatus:
    is_locked: bool = False
    retry_after_seconds: int = 0
    failure_count: int = 0

def _now() -> float:
    return time.monotonic()

class LoginRateLimiter:
    MAX_STORE_ENTRIES: int = 10000
    CLEANUP_INTERVAL_SECONDS: float = 30.0

    def __init__(
        self,
        max_user_ip_attempts: int = getattr(settings, "LOGIN_MAX_ATTEMPTS", 5),
        max_ip_attempts: int = getattr(settings, "LOGIN_MAX_ATTEMPTS", 5) * 3,
        lockout_seconds: int = getattr(settings, "LOGIN_LOCKOUT_SECONDS", 900),
        window_seconds: int = getattr(settings, "LOGIN_ATTEMPT_WINDOW_SECONDS", 600),
    ):
        self.max_user_ip_attempts = max_user_ip_attempts
        self.max_ip_attempts = max_ip_attempts
        self.lockout_seconds = lockout_seconds
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._last_cleanup: float = _now()

        # (username_lower, ip) -> (count, first_ts, locked_until_ts)
        self._user_ip_attempts: Dict[Tuple[str, str], Tuple[int, float, float]] = {}
        # ip -> (count, first_ts, locked_until_ts)
        self._ip_attempts: Dict[str, Tuple[int, float, float]] = {}
        # username_lower -> count (cumulative failures)
        self._user_attempts: Dict[str, int] = {}

    def _cleanup_expired(self, now: float) -> None:
        """Purge expired records to bound memory usage under attack."""
        # 1. Purge expired _user_ip_attempts
        expired_ui = [
            k for k, (count, first_ts, locked_until) in self._user_ip_attempts.items()
            if (locked_until > 0 and now >= locked_until) or
               (locked_until == 0 and (now - first_ts) > self.window_seconds)
        ]
        for k in expired_ui:
            del self._user_ip_attempts[k]

        # 2. Purge expired _ip_attempts
        expired_ip = [
            k for k, (count, first_ts, locked_until) in self._ip_attempts.items()
            if (locked_until > 0 and now >= locked_until) or
               (locked_until == 0 and (now - first_ts) > self.window_seconds)
        ]
        for k in expired_ip:
            del self._ip_attempts[k]

        # 3. If size still exceeds MAX_STORE_ENTRIES under extreme attack, evict oldest
        if len(self._user_ip_attempts) > self.MAX_STORE_ENTRIES:
            sorted_keys = sorted(self._user_ip_attempts.keys(), key=lambda k: self._user_ip_attempts[k][1])
            for k in sorted_keys[: len(self._user_ip_attempts) - self.MAX_STORE_ENTRIES]:
                del self._user_ip_attempts[k]

        if len(self._ip_attempts) > self.MAX_STORE_ENTRIES:
            sorted_keys = sorted(self._ip_attempts.keys(), key=lambda k: self._ip_attempts[k][1])
            for k in sorted_keys[: len(self._ip_attempts) - self.MAX_STORE_ENTRIES]:
                del self._ip_attempts[k]

    def _maybe_cleanup(self, now: float) -> None:
        if (now - self._last_cleanup) > self.CLEANUP_INTERVAL_SECONDS or len(self._user_ip_attempts) > (self.MAX_STORE_ENTRIES // 2):
            self._cleanup_expired(now)
            self._last_cleanup = now

    def _check_and_get(self, store: Dict, key: any) -> Tuple[int, float, float]:
        entry = store.get(key)
        if entry is None:
            return 0, 0.0, 0.0
        count, first_ts, locked_until = entry
        now = _now()
        if locked_until == 0.0 and (now - first_ts) > self.window_seconds:
            return 0, 0.0, 0.0
        return count, first_ts, locked_until

    def check_locked(self, username: str, ip: Optional[str]) -> LockStatus:
        with self._lock:
            now = _now()
            self._maybe_cleanup(now)
            u_key = username.lower() if username else ""
            ip_key = ip or "127.0.0.1"

            # 1. Check per-(username, IP) lockout
            ui_count, _, ui_locked_until = self._check_and_get(self._user_ip_attempts, (u_key, ip_key))
            if ui_locked_until > 0 and now < ui_locked_until:
                return LockStatus(
                    is_locked=True,
                    retry_after_seconds=int(ui_locked_until - now) + 1,
                    failure_count=ui_count,
                )

            # 2. Check per-IP lockout
            if ip:
                i_count, _, i_locked_until = self._check_and_get(self._ip_attempts, ip_key)
                if i_locked_until > 0 and now < i_locked_until:
                    return LockStatus(
                        is_locked=True,
                        retry_after_seconds=int(i_locked_until - now) + 1,
                        failure_count=i_count,
                    )

            return LockStatus(is_locked=False)

    def record_failure(self, username: str, ip: Optional[str]) -> LockStatus:
        with self._lock:
            now = _now()
            self._maybe_cleanup(now)
            u_key = username.lower() if username else ""
            ip_key = ip or "127.0.0.1"
            status = LockStatus(is_locked=False)

            # Update per-(user, IP)
            ui_count, ui_first, ui_locked = self._check_and_get(self._user_ip_attempts, (u_key, ip_key))
            if ui_first == 0.0:
                ui_first = now
            ui_count += 1
            ui_new_locked = 0.0
            if ui_count >= self.max_user_ip_attempts:
                ui_new_locked = now + self.lockout_seconds
                status = LockStatus(
                    is_locked=True,
                    retry_after_seconds=self.lockout_seconds,
                    failure_count=ui_count,
                )
            self._user_ip_attempts[(u_key, ip_key)] = (ui_count, ui_first, ui_new_locked)

            # Update per-IP
            if ip:
                i_count, i_first, i_locked = self._check_and_get(self._ip_attempts, ip_key)
                if i_first == 0.0:
                    i_first = now
                i_count += 1
                i_new_locked = 0.0
                if i_count >= self.max_ip_attempts:
                    i_new_locked = now + self.lockout_seconds
                    if not status.is_locked:
                        status = LockStatus(
                            is_locked=True,
                            retry_after_seconds=self.lockout_seconds,
                            failure_count=i_count,
                        )
                self._ip_attempts[ip_key] = (i_count, i_first, i_new_locked)

            self._user_attempts[u_key] = self._user_attempts.get(u_key, 0) + 1
            self._maybe_cleanup(now)
            return status

    def record_success(self, username: str, ip: Optional[str] = None) -> None:
        with self._lock:
            u_key = username.lower() if username else ""
            ip_key = ip or "127.0.0.1"
            self._user_ip_attempts.pop((u_key, ip_key), None)
            self._user_attempts.pop(u_key, None)

    def get_failure_count(self, username: str) -> int:
        with self._lock:
            u_key = username.lower() if username else ""
            return self._user_attempts.get(u_key, 0)

    def reset_all_for_tests(self) -> None:
        with self._lock:
            self._user_ip_attempts.clear()
            self._ip_attempts.clear()
            self._user_attempts.clear()
            self._last_cleanup = _now()

_default_limiter = LoginRateLimiter()

def check_locked(username: str, ip: Optional[str]) -> LockStatus:
    return _default_limiter.check_locked(username, ip)

def record_failure(username: str, ip: Optional[str]) -> LockStatus:
    return _default_limiter.record_failure(username, ip)

def record_success(username: str, ip: Optional[str] = None) -> None:
    _default_limiter.record_success(username, ip)

def get_failure_count(username: str) -> int:
    return _default_limiter.get_failure_count(username)

def reset_all_for_tests() -> None:
    _default_limiter.reset_all_for_tests()
