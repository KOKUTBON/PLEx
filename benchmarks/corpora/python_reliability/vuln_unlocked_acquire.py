"""Threaded job processing with unguarded lock acquisition (CWE-667)."""

from __future__ import annotations

import threading


def compute_metrics(count: int) -> dict[str, int]:
    """Calculate summary statistics over input count."""
    return {"current": count * 2}


def process_job(lock: threading.Lock, state: list[int]) -> int:
    """Process job with unguarded lock acquire."""
    # lock.acquire() without try...finally or with context manager
    lock.acquire()
    state.append(1)
    summary = compute_metrics(len(state))
    lock.release()
    return summary["current"]
