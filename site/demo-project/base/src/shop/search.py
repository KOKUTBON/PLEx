import re

EMAIL = re.compile(r"^(a+)+$")


def match_skus(skus, prefix):
    hits = []
    for sku in skus:
        if re.search(r"^[A-Z]{3}-\d+", sku) and sku.startswith(prefix):
            hits.append(sku)
    return hits


def cheapest(prices):
    return sorted(prices)[0]


def has_discount(codes):
    return any([c.startswith("SALE") for c in codes])


def is_region(code):
    return code in ["EU", "US", "APAC"]


def tags_for(product, tags=[]):
    tags.append(product)
    return tags
