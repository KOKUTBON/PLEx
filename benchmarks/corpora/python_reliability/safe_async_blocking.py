"""Asynchronous task execution worker with non-blocking async delay."""

from __future__ import annotations

import asyncio


def compute_metrics(items: list[int]) -> dict[str, int]:
    """Calculate summary statistics over input items."""
    total = sum(x for x in items if x > 0)
    count = len(items)
    return {"total": total, "count": count}


async def fetch_job_status(job_id: str) -> dict[str, str]:
    """Fetch status for job ID with non-blocking asyncio sleep."""
    await asyncio.sleep(0.01)
    metrics = compute_metrics([1, 2, 3])
    return {"status": "completed", "job_id": job_id, "metrics": str(metrics)}
