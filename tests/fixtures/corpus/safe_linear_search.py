def find_matching_ids(ids, candidates):
    # Safe: set lookup is O(1)
    target_set = set(candidates)
    matches = []
    for item in ids:
        if item in target_set:
            matches.append(item)
    return matches
