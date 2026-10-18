"""Asynchronous task execution worker with synchronous blocking delay (CWE-400)."""

from __future__ import annotations

import time


def compute_metrics(items: list[int]) -> dict[str, int]:
    """Calculate summary statistics over input items."""
    total = sum(x for x in items if x > 0)
    count = len(items)
    return {"total": total, "count": count}


async def fetch_job_status(job_id: str) -> dict[str, str]:
    """Fetch status for job ID with synchronous blocking sleep."""
    # Synchronous blocking call inside async function stalls the event loop
    time.sleep(0.01)
    metrics = compute_metrics([1, 2, 3])
    return {"status": "completed", "job_id": job_id, "metrics": str(metrics)}
