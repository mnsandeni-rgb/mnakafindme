#!/usr/bin/env python3

import hashlib
import json
import re
import sqlite3
import time

from licence_db import connect_licence_db
from auth_support import current_user, read_json


def ensure_activation_schema():
    """Add customer ownership without deleting existing records."""

    with connect_licence_db() as db:
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(licence_activations)"
            )
        }

        if "customer_user_id" not in columns:
            db.execute("""
                ALTER TABLE licence_activations
                ADD COLUMN customer_user_id INTEGER
            """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS activation_customer_idx
            ON licence_activations(customer_user_id, status)
        """)


def device_hash(device_id):
    return hashlib.sha256(
        device_id.encode("utf-8")
    ).hexdigest()


def licence_state(row, now):
    if row["status"] != "active":
        return "suspended" if row["status"] == "suspended" else "revoked"

    if now < row["starts_at"]:
        return "not_started"

    if row["expires_at"] is not None and now >= row["expires_at"]:
        return "expired"

    return "active"


def handle_licence_get(handler, path):
    if path != "/api/licence/status":
        return False

    user = current_user(handler)

    if user is None:
        handler.send_json(401, {
            "error": "Please sign in."
        })
        return True

    ensure_activation_schema()

    with connect_licence_db() as db:
        rows = db.execute("""
            SELECT
                l.licence_id,
                l.plan,
                l.status,
                l.starts_at,
                l.expires_at,
                l.max_devices
            FROM licences l
            WHERE lower(l.customer_email) = lower(?)
            ORDER BY l.created_at DESC
        """, (user["email"],)).fetchall()

        results = []

        for row in rows:
            state = licence_state(row, int(time.time()))

            devices = db.execute("""
                SELECT id, device_name, activated_at, last_seen
                FROM licence_activations
                WHERE licence_id = (
                    SELECT id FROM licences
                    WHERE licence_id = ?
                )
                AND customer_user_id = ?
                AND status = 'active'
            """, (row["licence_id"], user["id"])).fetchall()

            results.append({
                "licenceId": row["licence_id"],
                "plan": row["plan"],
                "status": state,
                "expiresAt": row["expires_at"],
                "maxDevices": row["max_devices"],
                "activeDevices": len(devices),
                "devices": [dict(d) for d in devices],
            })

    handler.send_json(200, {
        "licences": results
    })

    return True


def handle_licence_post(handler, path):
    routes = {
        "/api/licence/activate",
        "/api/licence/deactivate",
    }

    if path not in routes:
        return False

    user = current_user(handler)

    if user is None:
        handler.send_json(401, {
            "error": "Please sign in before managing licences."
        })
        return True

    data = read_json(handler)

    if data is None:
        handler.send_json(400, {
            "error": "Invalid JSON request."
        })
        return True

    now = int(time.time())

    if path == "/api/licence/activate":

        activation_key = data.get("activationKey")
        device_id = data.get("deviceId")
        device_name = data.get("deviceName", "Web browser")

        if not isinstance(activation_key, str):
            handler.send_json(400, {
                "error": "Enter a valid activation key."
            })
            return True

        if not 20 <= len(activation_key) <= 200:
            handler.send_json(400, {
                "error": "Invalid activation key."
            })
            return True

        if not isinstance(device_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{32,128}", device_id
        ):
            handler.send_json(400, {
                "error": "Invalid device identifier."
            })
            return True

        if (
            not isinstance(device_name, str)
            or len(device_name.strip()) > 80
        ):
            handler.send_json(400, {
                "error": "Invalid device name."
            })
            return True

        key_hash = hashlib.sha256(
            activation_key.encode("utf-8")
        ).hexdigest()

        hashed_device = device_hash(device_id)

        ensure_activation_schema()

        try:
            with connect_licence_db() as db:
                # Serialise activation attempts to enforce device limits.
                db.execute("BEGIN IMMEDIATE")

                licence = db.execute("""
                    SELECT * FROM licences
                    WHERE key_hash = ?
                """, (key_hash,)).fetchone()

                if licence is None:
                    handler.send_json(404, {
                        "error": "Invalid activation key."
                    })
                    return True

                if licence["customer_email"].lower() != user["email"].lower():
                    handler.send_json(403, {
                        "error": "This licence belongs to another customer."
                    })
                    return True

                state = licence_state(licence, now)

                if state != "active":
                    handler.send_json(403, {
                        "error": "Licence is not active.",
                        "status": state
                    })
                    return True

                existing = db.execute("""
                    SELECT * FROM licence_activations
                    WHERE licence_id = ?
                      AND device_hash = ?
                """, (
                    licence["id"],
                    hashed_device
                )).fetchone()

                if existing and existing["status"] == "active":

                    if (
                        existing["customer_user_id"] is not None
                        and existing["customer_user_id"] != user["id"]
                    ):
                        handler.send_json(403, {
                            "error": "Device belongs to another account."
                        })
                        return True

                    db.execute("""
                        UPDATE licence_activations
                        SET last_seen = ?,
                            customer_user_id = ?,
                            device_name = ?
                        WHERE id = ?
                    """, (
                        now,
                        user["id"],
                        device_name.strip() or "Web browser",
                        existing["id"]
                    ))

                else:
                    active_count = db.execute("""
                        SELECT COUNT(*)
                        FROM licence_activations
                        WHERE licence_id = ?
                          AND status = 'active'
                    """, (licence["id"],)).fetchone()[0]

                    if active_count >= licence["max_devices"]:
                        handler.send_json(409, {
                            "error": "Device activation limit reached.",
                            "maxDevices": licence["max_devices"],
                            "activeDevices": active_count
                        })
                        return True

                    if existing:
                        db.execute("""
                            UPDATE licence_activations
                            SET status = 'active',
                                customer_user_id = ?,
                                device_name = ?,
                                activated_at = ?,
                                last_seen = ?,
                                deactivated_at = NULL
                            WHERE id = ?
                        """, (
                            user["id"],
                            device_name.strip() or "Web browser",
                            now,
                            now,
                            existing["id"]
                        ))

                    else:
                        db.execute("""
                            INSERT INTO licence_activations (
                                licence_id,
                                device_hash,
                                device_name,
                                activated_at,
                                last_seen,
                                status,
                                customer_user_id
                            )
                            VALUES (?, ?, ?, ?, ?, 'active', ?)
                        """, (
                            licence["id"],
                            hashed_device,
                            device_name.strip() or "Web browser",
                            now,
                            now,
                            user["id"]
                        ))

                db.execute("""
                    INSERT INTO licence_audit (
                        licence_id,
                        action,
                        details,
                        performed_at
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    licence["id"],
                    "device_activated",
                    "Customer account ID: " + str(user["id"]),
                    now
                ))

            handler.send_json(200, {
                "ok": True,
                "message": "Device successfully activated.",
                "licenceId": licence["licence_id"],
                "plan": licence["plan"],
                "maxDevices": licence["max_devices"]
            })

        except sqlite3.Error:
            handler.send_json(500, {
                "error": "Licence activation could not be completed."
            })

        return True

    # Device deactivation
    device_id = data.get("deviceId")

    if not isinstance(device_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{32,128}", device_id
    ):
        handler.send_json(400, {
            "error": "Invalid device identifier."
        })
        return True

    ensure_activation_schema()

    try:
        with connect_licence_db() as db:
            db.execute("BEGIN IMMEDIATE")

            cursor = db.execute("""
                UPDATE licence_activations
                SET status = 'deactivated',
                    deactivated_at = ?
                WHERE device_hash = ?
                  AND customer_user_id = ?
                  AND status = 'active'
            """, (
                now,
                device_hash(device_id),
                user["id"]
            ))

            if cursor.rowcount != 1:
                handler.send_json(404, {
                    "error": "Active device not found."
                })
                return True

        handler.send_json(200, {
            "ok": True,
            "message": "Device successfully deactivated."
        })

    except sqlite3.Error:
        handler.send_json(500, {
            "error": "Device deactivation failed."
        })

    return True
