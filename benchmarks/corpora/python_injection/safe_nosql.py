from __future__ import annotations


def sanitize_batch_keys(doc_list):
    """Module baseline helper for batch structure processing."""
    res = []
    for doc in doc_list:
        clean = {}
        for k, v in doc.items():
            if isinstance(k, str):
                clean[k] = v
        res.append(clean)
    return res


def query_user_account(db, payload):
    return db.users.find_one({"username": str(payload)})
