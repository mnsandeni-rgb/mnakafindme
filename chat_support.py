import json
import sqlite3
import time
from urllib.parse import parse_qs

from auth_support import connect_db, current_user, send_json


MAX_MESSAGE_LENGTH = 4000


def init_chat_db():
    """Create the tables used by private conversations."""
    with connect_db() as db:
        db.execute("PRAGMA foreign_keys = ON")

        db.execute("""
            CREATE TABLE IF NOT EXISTS chat_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_low INTEGER NOT NULL,
                user_high INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(user_low, user_high),
                CHECK(user_low < user_high),
                FOREIGN KEY(user_low) REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(user_high) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                read_at INTEGER,
                FOREIGN KEY(conversation_id)
                    REFERENCES chat_conversations(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(sender_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                CHECK(length(body) BETWEEN 1 AND 4000)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS chat_messages_conversation_idx
            ON chat_messages(conversation_id, id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS chat_messages_unread_idx
            ON chat_messages(conversation_id, sender_id, read_at)
        """)


def _body(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if length < 1 or length > 12000:
            return None

        raw = handler.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _member(db, conversation_id, user_id):
    return db.execute("""
        SELECT id, user_low, user_high
        FROM chat_conversations
        WHERE id = ? AND (user_low = ? OR user_high = ?)
    """, (conversation_id, user_id, user_id)).fetchone()


def _conversation_id(value):
    try:
        result = int(value)
        return result if result > 0 else None
    except (TypeError, ValueError):
        return None


def handle_chat_get(handler, path, query=""):
    if path not in (
        "/api/chat/users",
        "/api/chat/conversations",
        "/api/chat/messages",
    ):
        return False

    user = current_user(handler)
    if user is None:
        send_json(handler, 401, {
            "error": "Please sign in to use ChatMe."
        })
        return True

    user_id = user["id"]
    params = parse_qs(query)

    if path == "/api/chat/users":
        search = params.get("q", [""])[0].strip()[:80]

        with connect_db() as db:
            if search:
                pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                rows = db.execute("""
                    SELECT id, full_name, username, account_type
                    FROM users
                    WHERE id != ?
                      AND (
                        full_name LIKE ? ESCAPE '\\'
                        OR username LIKE ? ESCAPE '\\'
                      )
                    ORDER BY username
                    LIMIT 50
                """, (user_id, pattern, pattern)).fetchall()
            else:
                rows = db.execute("""
                    SELECT id, full_name, username, account_type
                    FROM users
                    WHERE id != ?
                    ORDER BY username
                    LIMIT 50
                """, (user_id,)).fetchall()

        send_json(handler, 200, {
            "users": [
                {
                    "id": row["id"],
                    "fullName": row["full_name"],
                    "username": row["username"],
                    "accountType": row["account_type"],
                }
                for row in rows
            ]
        })
        return True

    if path == "/api/chat/conversations":
        with connect_db() as db:
            rows = db.execute("""
                SELECT
                    c.id,
                    CASE WHEN c.user_low = ?
                         THEN other.id ELSE other.id END AS other_id,
                    other.full_name AS other_name,
                    other.username AS other_username,
                    other.account_type AS other_type,
                    last.body AS last_message,
                    last.created_at AS last_message_at,
                    (
                        SELECT COUNT(*)
                        FROM chat_messages unread
                        WHERE unread.conversation_id = c.id
                          AND unread.sender_id != ?
                          AND unread.read_at IS NULL
                    ) AS unread_count
                FROM chat_conversations c
                JOIN users other
                  ON other.id = CASE
                      WHEN c.user_low = ? THEN c.user_high
                      ELSE c.user_low
                  END
                LEFT JOIN chat_messages last
                  ON last.id = (
                      SELECT MAX(m.id)
                      FROM chat_messages m
                      WHERE m.conversation_id = c.id
                  )
                WHERE c.user_low = ? OR c.user_high = ?
                ORDER BY COALESCE(last.created_at, c.created_at) DESC,
                         c.id DESC
            """, (
                user_id, user_id, user_id, user_id, user_id
            )).fetchall()

        send_json(handler, 200, {
            "conversations": [
                {
                    "id": row["id"],
                    "user": {
                        "id": row["other_id"],
                        "fullName": row["other_name"],
                        "username": row["other_username"],
                        "accountType": row["other_type"],
                    },
                    "lastMessage": row["last_message"] or "",
                    "lastMessageAt": row["last_message_at"],
                    "unreadCount": row["unread_count"],
                }
                for row in rows
            ]
        })
        return True

    conversation_id = _conversation_id(
        params.get("conversation_id", [""])[0]
    )

    if conversation_id is None:
        send_json(handler, 400, {
            "error": "A valid conversation ID is required."
        })
        return True

    try:
        before_id = int(params.get("before_id", ["0"])[0])
        if before_id < 0:
            raise ValueError
    except ValueError:
        send_json(handler, 400, {
            "error": "Invalid message cursor."
        })
        return True

    with connect_db() as db:
        if not _member(db, conversation_id, user_id):
            send_json(handler, 404, {
                "error": "Conversation not found."
            })
            return True

        if before_id:
            rows = db.execute("""
                SELECT m.id, m.sender_id, m.body, m.created_at,
                       m.read_at, u.username, u.full_name
                FROM chat_messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.conversation_id = ?
                  AND m.id < ?
                ORDER BY m.id DESC
                LIMIT 100
            """, (conversation_id, before_id)).fetchall()
            rows = list(reversed(rows))
        else:
            rows = db.execute("""
                SELECT m.id, m.sender_id, m.body, m.created_at,
                       m.read_at, u.username, u.full_name
                FROM chat_messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.conversation_id = ?
                ORDER BY m.id DESC
                LIMIT 100
            """, (conversation_id,)).fetchall()
            rows = list(reversed(rows))

        messages = [
            {
                "id": row["id"],
                "senderId": row["sender_id"],
                "senderName": row["full_name"],
                "username": row["username"],
                "body": row["body"],
                "createdAt": row["created_at"],
                "readAt": row["read_at"],
            }
            for row in rows
        ]

    send_json(handler, 200, {"messages": messages})
    return True


def handle_chat_post(handler, path):
    if path not in (
        "/api/chat/conversations",
        "/api/chat/messages",
        "/api/chat/read",
    ):
        return False

    user = current_user(handler)
    if user is None:
        send_json(handler, 401, {
            "error": "Please sign in to use ChatMe."
        })
        return True

    data = _body(handler)
    if data is None:
        send_json(handler, 400, {
            "error": "Send a valid JSON request."
        })
        return True

    user_id = user["id"]

    if path == "/api/chat/conversations":
        other_id = _conversation_id(data.get("userId"))

        if other_id is None or other_id == user_id:
            send_json(handler, 400, {
                "error": "Choose another registered user."
            })
            return True

        low, high = sorted((user_id, other_id))

        with connect_db() as db:
            other = db.execute(
                "SELECT id FROM users WHERE id = ?", (other_id,)
            ).fetchone()

            if other is None:
                send_json(handler, 404, {
                    "error": "That user does not exist."
                })
                return True

            db.execute("""
                INSERT OR IGNORE INTO chat_conversations
                    (user_low, user_high, created_at)
                VALUES (?, ?, ?)
            """, (low, high, int(time.time())))

            row = db.execute("""
                SELECT id FROM chat_conversations
                WHERE user_low = ? AND user_high = ?
            """, (low, high)).fetchone()

        send_json(handler, 200, {
            "ok": True,
            "conversationId": row["id"],
        })
        return True

    conversation_id = _conversation_id(data.get("conversationId"))

    if conversation_id is None:
        send_json(handler, 400, {
            "error": "A valid conversation ID is required."
        })
        return True

    with connect_db() as db:
        if not _member(db, conversation_id, user_id):
            send_json(handler, 404, {
                "error": "Conversation not found."
            })
            return True

        if path == "/api/chat/messages":
            body = data.get("body")

            if not isinstance(body, str):
                send_json(handler, 400, {
                    "error": "Enter a message."
                })
                return True

            body = body.strip()

            if not body or len(body) > MAX_MESSAGE_LENGTH:
                send_json(handler, 400, {
                    "error": "Messages must contain 1–4000 characters."
                })
                return True

            now = int(time.time())

            cursor = db.execute("""
                INSERT INTO chat_messages
                    (conversation_id, sender_id, body, created_at)
                VALUES (?, ?, ?, ?)
            """, (conversation_id, user_id, body, now))

            message_id = cursor.lastrowid

            send_json(handler, 201, {
                "ok": True,
                "message": {
                    "id": message_id,
                    "senderId": user_id,
                    "senderName": user["fullName"],
                    "username": user["username"],
                    "body": body,
                    "createdAt": now,
                    "readAt": None,
                }
            })
            return True

        db.execute("""
            UPDATE chat_messages
            SET read_at = ?
            WHERE conversation_id = ?
              AND sender_id != ?
              AND read_at IS NULL
        """, (int(time.time()), conversation_id, user_id))

    send_json(handler, 200, {"ok": True})
    return True
