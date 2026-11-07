import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path
from http.cookies import SimpleCookie

DB_PATH = Path(__file__).resolve().parent / "findme.db"
SESSION_COOKIE = "mnakaa_session"
SESSION_LIFETIME = 60 * 60 * 24 * 7
PASSWORD_ITERATIONS = 600_000


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_auth_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                account_type TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS sessions_user_id_idx
            ON sessions(user_id)
        """)

        db.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (int(time.time()),)
        )


def send_json(handler, status, data, extra_headers=None):
    body = json.dumps(data).encode("utf-8")

    handler.send_response(status)
    handler.send_header(
        "Content-Type", "application/json; charset=utf-8"
    )
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")

    if extra_headers:
        for name, value in extra_headers:
            handler.send_header(name, value)

    handler.end_headers()
    handler.wfile.write(body)


def public_user(row):
    return {
        "id": row["id"],
        "fullName": row["full_name"],
        "username": row["username"],
        "email": row["email"],
        "accountType": row["account_type"],
    }


def current_user(handler):
    cookie = SimpleCookie()

    try:
        cookie.load(handler.headers.get("Cookie", ""))
        token = cookie[SESSION_COOKIE].value
    except (KeyError, Exception):
        return None

    if not re.fullmatch(r"[0-9a-f]{64}", token):
        return None

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with connect_db() as db:
        row = db.execute("""
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
              AND sessions.expires_at > ?
        """, (token_hash, int(time.time()))).fetchone()

    return public_user(row) if row else None


def make_session(user_id):
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = int(time.time()) + SESSION_LIFETIME

    with connect_db() as db:
        db.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (int(time.time()),)
        )
        db.execute("""
            INSERT INTO sessions(token_hash, user_id, expires_at)
            VALUES (?, ?, ?)
        """, (token_hash, user_id, expires))

    cookie = (
        f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; "
        f"SameSite=Strict; Max-Age={SESSION_LIFETIME}"
    )

    return [("Set-Cookie", cookie)]


def clear_session(handler):
    cookie = SimpleCookie()

    try:
        cookie.load(handler.headers.get("Cookie", ""))
        token = cookie[SESSION_COOKIE].value

        if re.fullmatch(r"[0-9a-f]{64}", token):
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            with connect_db() as db:
                db.execute(
                    "DELETE FROM sessions WHERE token_hash = ?",
                    (token_hash,)
                )
    except Exception:
        pass

    return [(
        "Set-Cookie",
        f"{SESSION_COOKIE}=; Path=/; HttpOnly; "
        "SameSite=Strict; Max-Age=0"
    )]


def read_json(handler):
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower():
        return None

    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return None

    if length < 1 or length > 16_384:
        return None

    try:
        data = json.loads(handler.rfile.read(length))
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


def handle_auth_get(handler, path):
    if path != "/api/auth/me":
        return False

    user = current_user(handler)

    send_json(handler, 200, {
        "authenticated": user is not None,
        "user": user
    })
    return True


def handle_auth_post(handler, path):
    routes = {
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/logout",
    }

    if path not in routes:
        return False

    data = read_json(handler)

    if data is None:
        send_json(handler, 400, {
            "error": "Send a valid JSON request."
        })
        return True

    if path == "/api/auth/logout":
        headers = clear_session(handler)
        send_json(handler, 200, {
            "ok": True,
            "message": "You have signed out."
        }, headers)
        return True

    if path == "/api/auth/register":
        full_name = str(data.get("fullName", "")).strip()
        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = data.get("password", "")
        account_type = data.get("accountType", "")

        if not all(isinstance(v, str) for v in (
            data.get("fullName", ""),
            data.get("username", ""),
            data.get("email", ""),
            password,
            account_type,
        )):
            send_json(handler, 400, {
                "error": "Please check the registration fields."
            })
            return True

        if not 2 <= len(full_name) <= 100:
            send_json(handler, 400, {
                "error": "Enter your full name."
            })
            return True

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            send_json(handler, 400, {
                "error": (
                    "Username must be 3–30 characters using "
                    "letters, numbers or underscores."
                )
            })
            return True

        if len(email) > 254 or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            send_json(handler, 400, {
                "error": "Enter a valid email address."
            })
            return True

        if len(password) < 10 or len(password) > 1024:
            send_json(handler, 400, {
                "error": "Password must contain at least 10 characters."
            })
            return True

        if account_type not in ("Customer", "Salesperson", "Both"):
            send_json(handler, 400, {
                "error": "Choose a valid account type."
            })
            return True

        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            salt, PASSWORD_ITERATIONS
        ).hex()

        try:
            with connect_db() as db:
                cursor = db.execute("""
                    INSERT INTO users (
                        full_name, username, email,
                        password_hash, password_salt,
                        account_type, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    full_name, username, email,
                    password_hash, salt.hex(),
                    account_type, int(time.time())
                ))

                user_id = cursor.lastrowid

                user = public_user(db.execute(
                    "SELECT * FROM users WHERE id = ?",
                    (user_id,)
                ).fetchone())

        except sqlite3.IntegrityError:
            send_json(handler, 409, {
                "error": "That username or email is already registered."
            })
            return True

        headers = make_session(user["id"])

        send_json(handler, 201, {
            "ok": True,
            "user": user
        }, headers)
        return True

    # Sign in
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        send_json(handler, 400, {
            "error": "Enter your username and password."
        })
        return True

    if len(username) > 254 or len(password) > 1024:
        send_json(handler, 400, {
            "error": "Invalid username or password."
        })
        return True

    with connect_db() as db:
        row = db.execute("""
            SELECT * FROM users
            WHERE username = ? OR email = ?
            LIMIT 1
        """, (username.strip(), username.strip().lower())).fetchone()

    if row is None:
        # Perform a password hash operation even for an unknown user.
        hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes(16), PASSWORD_ITERATIONS
        )

        send_json(handler, 401, {
            "error": "Incorrect username/email or password."
        })
        return True

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(row["password_salt"]),
        PASSWORD_ITERATIONS
    ).hex()

    if not hmac.compare_digest(expected, row["password_hash"]):
        send_json(handler, 401, {
            "error": "Incorrect username/email or password."
        })
        return True

    user = public_user(row)
    headers = make_session(user["id"])

    send_json(handler, 200, {
        "ok": True,
        "user": user
    }, headers)
    return True
