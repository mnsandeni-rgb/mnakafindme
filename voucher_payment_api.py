import sqlite3, time, json
from pathlib import Path
from auth_support import current_user, read_json, send_json

DB = Path(__file__).parent / "findme.db"

def init_voucher_payment_db():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS voucher_payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, voucher_code TEXT, amount REAL, status TEXT DEFAULT 'pending', created_at INTEGER)")
        db.commit()

def handle_voucher_payment_get(handler, path):
    if path != "/api/voucher/status":
        return False
    send_json(handler, {"ok": True, "voucher": None})
    return True

def handle_voucher_payment_post(handler, path):
    if path != "/api/voucher/redeem":
        return False
    data = read_json(handler)
    send_json(handler, {"ok": True, "message": "Voucher placeholder - not yet implemented", "data": data})
    return True
