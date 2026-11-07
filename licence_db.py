#!/usr/bin/env python3

import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parent
LICENCE_DIR = BASE / "licences"
DB_PATH = LICENCE_DIR / "licences.db"


def connect_licence_db():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_licence_db():

    LICENCE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    with connect_licence_db() as db:

        # Main customer licence records
        db.execute("""
            CREATE TABLE IF NOT EXISTS licences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                licence_id TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL UNIQUE,

                customer_name TEXT NOT NULL,
                customer_email TEXT NOT NULL,
                business_name TEXT NOT NULL DEFAULT '',

                plan TEXT NOT NULL CHECK (
                    plan IN (
                        'trial',
                        'daily',
                        'monthly',
                        'annual',
                        'lifetime'
                    )
                ),

                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (
                        status IN (
                            'active',
                            'suspended',
                            'revoked'
                        )
                    ),

                issued_at INTEGER NOT NULL,
                starts_at INTEGER NOT NULL,
                expires_at INTEGER,

                max_devices INTEGER NOT NULL DEFAULT 1
                    CHECK (max_devices BETWEEN 1 AND 100),

                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,

                notes TEXT NOT NULL DEFAULT '',

                CHECK (
                    (plan = 'lifetime' AND expires_at IS NULL)
                    OR
                    (plan != 'lifetime' AND expires_at IS NOT NULL)
                )
            )
        """)

        # Customer device activations
        db.execute("""
            CREATE TABLE IF NOT EXISTS licence_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                licence_id INTEGER NOT NULL,

                device_hash TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',

                activated_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,

                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (
                        status IN (
                            'active',
                            'deactivated'
                        )
                    ),

                deactivated_at INTEGER,

                FOREIGN KEY (licence_id)
                    REFERENCES licences(id)
                    ON DELETE RESTRICT,

                UNIQUE (licence_id, device_hash)
            )
        """)

        # Licence renewal history
        db.execute("""
            CREATE TABLE IF NOT EXISTS licence_renewals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                licence_id INTEGER NOT NULL,

                previous_expiry INTEGER,
                new_expiry INTEGER,

                previous_plan TEXT NOT NULL,
                new_plan TEXT NOT NULL,

                renewed_at INTEGER NOT NULL,
                notes TEXT NOT NULL DEFAULT '',

                FOREIGN KEY (licence_id)
                    REFERENCES licences(id)
                    ON DELETE RESTRICT
            )
        """)

        # Owner audit trail
        db.execute("""
            CREATE TABLE IF NOT EXISTS licence_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                licence_id INTEGER,

                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',

                performed_at INTEGER NOT NULL,

                FOREIGN KEY (licence_id)
                    REFERENCES licences(id)
                    ON DELETE RESTRICT
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS licence_customer_idx
            ON licences(customer_email)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS licence_status_idx
            ON licences(status)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS activation_licence_idx
            ON licence_activations(licence_id, status)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS renewal_licence_idx
            ON licence_renewals(licence_id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS audit_licence_idx
            ON licence_audit(licence_id)
        """)

    DB_PATH.chmod(0o600)

    return DB_PATH


if __name__ == "__main__":

    path = init_licence_db()

    print("=" * 45)
    print("MNAKAFINDME LICENCE DATABASE")
    print("=" * 45)
    print("Database:", path)
    print("Status: INITIALISED")
    print("Existing customer database: UNCHANGED")
    print("=" * 45)
