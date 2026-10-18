"""Threaded job processing with properly guarded lock acquisition."""

from __future__ import annotations

import threading


def compute_metrics(count: int) -> dict[str, int]:
    """Calculate summary statistics over input count."""
    return {"current": count * 2}


def process_job(lock: threading.Lock, state: list[int]) -> int:
    """Process job guarded with try...finally."""
    lock.acquire()
    try:
        state.append(1)
        summary = compute_metrics(len(state))
        return summary["current"]
    finally:
        lock.release()
