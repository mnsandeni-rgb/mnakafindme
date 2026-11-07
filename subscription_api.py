import sqlite3, time, json
from pathlib import Path
from auth_support import current_user, read_json, send_json

DB = Path(__file__).parent / "findme.db"

def init_subscription_db():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan TEXT, status TEXT DEFAULT 'active', starts_at INTEGER, expires_at INTEGER, created_at INTEGER)")
        db.commit()

def handle_subscription_get(handler, path):
    if path != "/api/subscription/status":
        return False
    user = current_user(handler)
    send_json(handler, {"ok": True, "subscription": None, "user": user})
    return True

def handle_subscription_post(handler, path):
    if path != "/api/subscription/create":
        return False
    data = read_json(handler)
    send_json(handler, {"ok": True, "message": "Subscription placeholder - not yet implemented", "data": data})
    return True
