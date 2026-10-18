from __future__ import annotations

from functools import wraps


class DummyApp:
    def post(self, path: str):
        def _wrap(fn):
            return fn
        return _wrap


app = DummyApp()


def admin_required(fn):
    @wraps(fn)
    def _guarded(request, *args, **kwargs):
        if getattr(request.user, "role", None) != "admin":
            raise PermissionError("Forbidden: admin role required")
        return fn(request, *args, **kwargs)
    return _guarded


def delete_user(db, user_id: str) -> dict[str, str]:
    db.remove(user_id)
    return {"deleted": user_id}


@app.post("/admin/users/delete")
@admin_required
def admin_delete_user(request, db):
    target_id = request.json.get("user_id")
    return delete_user(db, target_id)
