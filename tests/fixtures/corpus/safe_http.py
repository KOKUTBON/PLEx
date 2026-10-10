def fetch_batch(client, ids):
    # Safe: single batch request outside loop
    response = client.get("/api/batch", params={"ids": ids})
    items = response.json()
    results = []
    for item in items:
        results.append(item.get("value"))
    return results
