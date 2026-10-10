import copy


def process_prototypes(items: list[dict], template: dict) -> list[dict]:
    # Safe: deepcopy done once outside loop
    base_copy = copy.deepcopy(template)
    results = []
    for item in items:
        # Shallow copy or update inside loop
        new_item = base_copy.copy()
        new_item["id"] = item["id"]
        results.append(new_item)
    return results
