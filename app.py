import os
import secrets
from copy import deepcopy
from functools import wraps

from flask import Flask, abort, jsonify, request

app = Flask(__name__)

LAB_MODE = os.getenv("LAB_MODE", "vuln").strip().lower()
if LAB_MODE not in {"vuln", "fixed"}:
    LAB_MODE = "vuln"

SEED_USERS = {
    1: {"id": 1, "username": "alice", "password": "alice123", "role": "user"},
    2: {"id": 2, "username": "bob", "password": "bob123", "role": "user"},
    3: {"id": 3, "username": "admin", "password": "admin123", "role": "admin"},
}

SEED_NOTES = {
    1: [{"id": 101, "text": "Alice private note"}],
    2: [{"id": 201, "text": "Bob payroll draft"}],
    3: [{"id": 301, "text": "Admin incident report"}],
}

USERS = deepcopy(SEED_USERS)
NOTES = deepcopy(SEED_NOTES)
TOKENS = {}


def issue_token(user):
    token = secrets.token_urlsafe(24)
    TOKENS[token] = user["id"]
    return token


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ").strip()
    user_id = TOKENS.get(token)
    return USERS.get(user_id)


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            abort(401, description="Missing or invalid token")
        request.user = user
        return fn(*args, **kwargs)

    return wrapper


def enforce_owner_or_admin(target_user_id):
    user = request.user
    if user["id"] == target_user_id:
        return
    if user["role"] == "admin":
        return
    abort(403, description="Forbidden")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "mode": LAB_MODE})


@app.post("/reset")
def reset_data():
    USERS.clear()
    USERS.update(deepcopy(SEED_USERS))
    NOTES.clear()
    NOTES.update(deepcopy(SEED_NOTES))
    TOKENS.clear()
    return jsonify({"status": "reset"})


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    user = next((u for u in USERS.values() if u["username"] == username), None)
    if not user or user["password"] != password:
        abort(401, description="Invalid credentials")

    token = issue_token(user)
    return jsonify({"token": token, "user": {"id": user["id"], "role": user["role"]}})


@app.get("/me")
@require_auth
def me():
    user = request.user
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})


@app.get("/api/users/<int:user_id>/notes")
@require_auth
def read_user_notes(user_id):
    # CWE-284 (vuln mode): missing object-level authorization.
    if LAB_MODE == "fixed":
        enforce_owner_or_admin(user_id)

    return jsonify({"owner_id": user_id, "notes": NOTES.get(user_id, [])})


@app.get("/api/admin/audit")
@require_auth
def admin_audit_log():
    # CWE-284 (vuln mode): admin endpoint exposed to all authenticated users.
    if LAB_MODE == "fixed" and request.user["role"] != "admin":
        abort(403, description="Admin only")

    return jsonify(
        {
            "entries": [
                "[2026-04-01] Role update: bob -> user",
                "[2026-04-02] Sensitive system event",
            ]
        }
    )


@app.delete("/api/users/<int:user_id>")
@require_auth
def delete_user(user_id):
    # CWE-284 (vuln mode): any authenticated user can perform destructive action.
    if LAB_MODE == "fixed" and request.user["role"] != "admin":
        abort(403, description="Admin only")

    if user_id not in USERS:
        abort(404, description="User not found")

    deleted = USERS.pop(user_id)
    NOTES.pop(user_id, None)

    stale_tokens = [token for token, uid in TOKENS.items() if uid == user_id]
    for token in stale_tokens:
        TOKENS.pop(token, None)

    return jsonify({"deleted": {"id": deleted["id"], "username": deleted["username"]}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
