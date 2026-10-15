import heapq


def analyze_scores(scores: list[float], limit: int) -> list[float]:
    # Safe: sorted once outside loop
    sorted_scores = sorted(scores, reverse=True)
    accumulated = []
    for s in sorted_scores[:limit]:
        accumulated.append(s * 1.1)
    return accumulated


def top_k_stream(stream: list[int], k: int) -> list[int]:
    # Safe: maintaining top-k with heap inside loop instead of full sorts
    heap: list[int] = []
    for val in stream:
        if len(heap) < k:
            heapq.heappush(heap, val)
        elif val > heap[0]:
            heapq.heapreplace(heap, val)
    return sorted(heap)
