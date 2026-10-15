import asyncio


async def fetch_item(client, item_id: str) -> dict:
    # Safe: uses non-blocking asyncio.sleep and async call
    await asyncio.sleep(0.01)
    response = await client.get(f"/items/{item_id}")
    return response


def sync_blocking_worker(path: str) -> str:
    # Safe: synchronous helper function outside of async def
    with open(path) as f:
        return f.read()
