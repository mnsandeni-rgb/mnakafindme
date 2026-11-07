#!/usr/bin/env python3

import hashlib
import json
import os
import secrets
import time
import uuid

from pathlib import Path

from licence_db import connect_licence_db
from licence_support import create_signed_licence, verify_signed_licence

BASE = Path(__file__).resolve().parent
OUTPUT_DIR = BASE / "customer_licences"

PLAN_DAYS = {
    "trial": 14,
    "daily": 1,
    "monthly": 30,
    "annual": 365,
    "lifetime": None,
}


def issue_licence(
    customer_name,
    customer_email,
    business_name,
    plan,
    max_devices=1,
    notes=""
):
    if plan not in PLAN_DAYS:
        raise ValueError("Invalid licence plan.")

    if not customer_name.strip() or not customer_email.strip():
        raise ValueError("Customer name and email are required.")

    if not 1 <= max_devices <= 100:
        raise ValueError("Device limit must be between 1 and 100.")

    now = int(time.time())

    expires_at = (
        None if PLAN_DAYS[plan] is None
        else now + PLAN_DAYS[plan] * 86400
    )

    licence_id = "MNF-" + uuid.uuid4().hex.upper()

    activation_key = secrets.token_urlsafe(32)

    payload = {
        "application": "MnakaFindMe",
        "licence_id": licence_id,
        "customer_name": customer_name.strip(),
        "customer_email": customer_email.strip().lower(),
        "business_name": business_name.strip(),
        "plan": plan,
        "issued_at": now,
        "starts_at": now,
        "expires_at": expires_at,
        "max_devices": max_devices,
        "activation_key": activation_key,
    }

    # Sign the licence before recording it.
    document = create_signed_licence(payload)

    # Independently verify the signature.
    valid, verified_payload = verify_signed_licence(document)

    if not valid or verified_payload != payload:
        raise RuntimeError("Licence signature verification failed.")

    OUTPUT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    OUTPUT_DIR.chmod(0o700)

    output_file = OUTPUT_DIR / f"{licence_id}.json"
    temporary_file = OUTPUT_DIR / f".{licence_id}.tmp"

    if output_file.exists():
        raise FileExistsError("Licence output already exists.")

    key_hash = hashlib.sha256(
        activation_key.encode("utf-8")
    ).hexdigest()

    created_output = False
    db = None

    try:
        with open(temporary_file, "x", encoding="utf-8") as file:
            json.dump(document, file, indent=4, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.chmod(temporary_file, 0o600)

        db = connect_licence_db()

        cursor = db.execute("""
            INSERT INTO licences (
                licence_id, key_hash, customer_name,
                customer_email, business_name, plan,
                status, issued_at, starts_at, expires_at,
                max_devices, created_at, updated_at, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, 'active',
                    ?, ?, ?, ?, ?, ?, ?)
        """, (
            licence_id,
            key_hash,
            payload["customer_name"],
            payload["customer_email"],
            payload["business_name"],
            plan,
            now,
            now,
            expires_at,
            max_devices,
            now,
            now,
            notes
        ))

        db.execute("""
            INSERT INTO licence_audit (
                licence_id, action, details, performed_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            cursor.lastrowid,
            "licence_issued",
            f"Plan: {plan}; Devices: {max_devices}",
            now
        ))

        # Atomically create the final filename without overwriting.
        os.link(temporary_file, output_file)
        created_output = True
        temporary_file.unlink()

        # Commit the licence and audit record together.
        db.commit()

    except Exception:
        if db is not None:
            db.rollback()

        temporary_file.unlink(missing_ok=True)

        if created_output:
            output_file.unlink(missing_ok=True)

        raise

    finally:
        if db is not None:
            db.close()

    return licence_id, output_file


def main():

    print("=" * 50)
    print("MNAKAFINDME OWNER LICENCE GENERATOR")
    print("=" * 50)

    customer_name = input("Customer name: ").strip()
    customer_email = input("Customer email: ").strip()
    business_name = input("Business name: ").strip()

    print("\nAvailable plans:")
    print("1. Trial (14 days)")
    print("2. Daily (24 hours)")
    print("3. Monthly (30 days)")
    print("4. Annual (365 days)")
    print("5. Lifetime")

    choices = {
        "1": "trial",
        "2": "daily",
        "3": "monthly",
        "4": "annual",
        "5": "lifetime",
    }

    plan_choice = input("\nSelect plan (1-5): ").strip()

    if plan_choice not in choices:
        raise ValueError("Invalid plan selection.")

    max_devices = int(
        input("Maximum authorised devices (default 1): ") or "1"
    )

    notes = input("Owner notes (optional): ").strip()

    licence_id, output_file = issue_licence(
        customer_name,
        customer_email,
        business_name,
        choices[plan_choice],
        max_devices,
        notes
    )

    print("\n" + "=" * 50)
    print("LICENCE SUCCESSFULLY GENERATED")
    print("=" * 50)
    print("Licence ID:", licence_id)
    print("Plan:", choices[plan_choice])
    print("File:", output_file)
    print("Digital signature: VERIFIED")
    print("Database record: CREATED")
    print("=" * 50)


if __name__ == "__main__":
    main()
