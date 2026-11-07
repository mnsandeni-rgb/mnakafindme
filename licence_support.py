#!/usr/bin/env python3

import base64
import json

from pathlib import Path

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY = (
    Path(__file__).resolve().parent
    / "licence_keys"
    / "owner_private.key"
)

PUBLIC_KEY = (
    Path(__file__).resolve().parent
    / "licence_keys"
    / "customer_public.key"
)


def canonical_json(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def create_signed_licence(payload):
    if not PRIVATE_KEY.is_file():
        raise FileNotFoundError("Owner signing key unavailable.")

    private_key = Ed25519PrivateKey.from_private_bytes(
        PRIVATE_KEY.read_bytes()
    )

    signature = private_key.sign(canonical_json(payload))

    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii")
    }


def verify_signed_licence(document, public_key_path=None):
    public_path = Path(public_key_path or PUBLIC_KEY)

    try:
        if not public_path.is_file():
            return False, None

        payload = document["payload"]
        signature = base64.b64decode(
            document["signature"],
            validate=True
        )

        if payload.get("application") != "MnakaFindMe":
            return False, None

        public_key = Ed25519PublicKey.from_public_bytes(
            public_path.read_bytes()
        )

        public_key.verify(
            signature,
            canonical_json(payload)
        )

        return True, payload

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        AttributeError
    ):
        return False, None
