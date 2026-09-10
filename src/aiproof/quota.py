"""In-process quotas: requests per minute, tokens per day, prompt size.

Quotas are the one place where aiproof is fail-closed by design: exceeding a
limit raises ``QuotaExceeded`` before the model is called. Counters live in
memory per process; for cluster-wide limits put a gateway in front and keep
these as a last line.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple


class QuotaExceeded(RuntimeError):
    def __init__(self, kind: str, limit: int, current: int):
        super().__init__(f"quota exceeded: {kind} limit={limit} current={current}")
        self.kind = kind
        self.limit = limit
        self.current = current


class QuotaTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._req: Deque[float] = deque()
        self._tokens_day: Dict[str, int] = {}  # "YYYY-MM-DD" -> tokens

    def check_request(self, rpm: int, prompt_chars: int, max_prompt_chars: int) -> None:
        if max_prompt_chars and prompt_chars > max_prompt_chars:
            raise QuotaExceeded("prompt_chars", max_prompt_chars, prompt_chars)
        if not rpm:
            return
        now = time.time()
        with self._lock:
            while self._req and now - self._req[0] > 60:
                self._req.popleft()
            if len(self._req) >= rpm:
                raise QuotaExceeded("requests_per_minute", rpm, len(self._req))
            self._req.append(now)

    def add_tokens(self, n: int, max_per_day: int) -> Tuple[int, bool]:
        """Record tokens; return (today_total, over_limit)."""
        day = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock:
            # drop old days
            for k in list(self._tokens_day):
                if k != day:
                    del self._tokens_day[k]
            self._tokens_day[day] = self._tokens_day.get(day, 0) + max(0, int(n or 0))
            total = self._tokens_day[day]
        return total, bool(max_per_day and total > max_per_day)

    def check_tokens(self, max_per_day: int) -> None:
        if not max_per_day:
            return
        day = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock:
            total = self._tokens_day.get(day, 0)
        if total >= max_per_day:
            raise QuotaExceeded("tokens_per_day", max_per_day, total)


_global = QuotaTracker()


def tracker() -> QuotaTracker:
    return _global
