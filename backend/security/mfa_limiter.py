import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional


@dataclass
class MFALockStatus:
    is_locked: bool = False
    retry_after_seconds: int = 0
    failure_count: int = 0


class MFARateLimiter:
    """
    Lightweight in-process limiter for MFA verification attempts.

    Tracks:
      - (user_id, IP) independently
      - IP independently
    """

    def __init__(
        self,
        max_user_ip_attempts: int = 5,
        max_ip_attempts: int = 20,
        lockout_seconds: int = 300,
        window_seconds: int = 600,
        max_entries: int = 10000,
    ):
        self.max_user_ip_attempts = max_user_ip_attempts
        self.max_ip_attempts = max_ip_attempts
        self.lockout_seconds = lockout_seconds
        self.window_seconds = window_seconds
        self.max_entries = max_entries

        self._lock = threading.Lock()
        self._user_ip_attempts: Dict[
            Tuple[int, str], Tuple[int, float, float]
        ] = {}
        self._ip_attempts: Dict[
            str, Tuple[int, float, float]
        ] = {}

    def _now(self) -> float:
        return time.monotonic()

    def _get_entry(self, store: Dict, key):
        entry = store.get(key)
        if entry is None:
            return 0, 0.0, 0.0

        count, first_ts, locked_until = entry
        now = self._now()

        if locked_until == 0.0 and (now - first_ts) > self.window_seconds:
            return 0, 0.0, 0.0

        return count, first_ts, locked_until

    def _cleanup(self) -> None:
        now = self._now()

        for store in (self._user_ip_attempts, self._ip_attempts):
            expired = [
                key
                for key, (_, first_ts, locked_until) in store.items()
                if (
                    (locked_until != 0.0 and now >= locked_until)
                    or (
                        locked_until == 0.0
                        and (now - first_ts) > self.window_seconds
                    )
                )
            ]

            for key in expired:
                store.pop(key, None)

            if len(store) > self.max_entries:
                excess = len(store) - self.max_entries
                oldest = sorted(
                    store.items(),
                    key=lambda item: item[1][1]
                )[:excess]

                for key, _ in oldest:
                    store.pop(key, None)

    def check_locked(
        self,
        user_id: int,
        ip: Optional[str]
    ) -> MFALockStatus:
        with self._lock:
            self._cleanup()

            ip_key = ip or "unknown"
            user_key = (user_id, ip_key)
            now = self._now()

            user_count, _, user_locked = self._get_entry(
                self._user_ip_attempts,
                user_key
            )

            if user_locked > now:
                return MFALockStatus(
                    is_locked=True,
                    retry_after_seconds=int(user_locked - now) + 1,
                    failure_count=user_count,
                )

            if ip:
                ip_count, _, ip_locked = self._get_entry(
                    self._ip_attempts,
                    ip_key
                )

                if ip_locked > now:
                    return MFALockStatus(
                        is_locked=True,
                        retry_after_seconds=int(ip_locked - now) + 1,
                        failure_count=ip_count,
                    )

            return MFALockStatus()

    def record_failure(
        self,
        user_id: int,
        ip: Optional[str]
    ) -> MFALockStatus:
        with self._lock:
            self._cleanup()

            ip_key = ip or "unknown"
            user_key = (user_id, ip_key)
            now = self._now()

            status = MFALockStatus()

            # Per-user + IP
            count, first_ts, locked_until = self._get_entry(
                self._user_ip_attempts,
                user_key
            )

            if first_ts == 0.0:
                first_ts = now

            count += 1
            new_locked_until = 0.0

            if count >= self.max_user_ip_attempts:
                new_locked_until = now + self.lockout_seconds
                status = MFALockStatus(
                    is_locked=True,
                    retry_after_seconds=self.lockout_seconds,
                    failure_count=count,
                )

            self._user_ip_attempts[user_key] = (
                count,
                first_ts,
                new_locked_until,
            )

            # Per-IP
            if ip:
                ip_count, ip_first, ip_locked = self._get_entry(
                    self._ip_attempts,
                    ip_key
                )

                if ip_first == 0.0:
                    ip_first = now

                ip_count += 1
                ip_new_locked = 0.0

                if ip_count >= self.max_ip_attempts:
                    ip_new_locked = now + self.lockout_seconds

                    if not status.is_locked:
                        status = MFALockStatus(
                            is_locked=True,
                            retry_after_seconds=self.lockout_seconds,
                            failure_count=ip_count,
                        )

                self._ip_attempts[ip_key] = (
                    ip_count,
                    ip_first,
                    ip_new_locked,
                )

            return status

    def record_success(
        self,
        user_id: int,
        ip: Optional[str]
    ) -> None:
        with self._lock:
            ip_key = ip or "unknown"
            self._user_ip_attempts.pop((user_id, ip_key), None)


mfa_rate_limiter = MFARateLimiter()
