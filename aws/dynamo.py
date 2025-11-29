import os
import json
import time
import hmac
import base64
import hashlib

import boto3

# ---- CONFIG ----

USERS_TABLE = os.environ.get("USERS_TABLE", "Users")
BLACKLIST_TABLE = os.environ.get("TOKEN_BLACKLIST", "TokenBlacklist")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")

dynamo = boto3.resource("dynamodb")
users_table = dynamo.Table(USERS_TABLE)
blacklist_table = dynamo.Table(BLACKLIST_TABLE)


# ---- PASSWORD HASHING ----

def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password is empty")

    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, good_hash = stored.split("$", 1)
    except ValueError:
        return False

    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, good_hash)


# ---- TOKEN CREATION ----

def create_token(email: str, ttl_seconds: int = 3600) -> str:
    payload = {
        "email": email,
        "exp": int(time.time()) + ttl_seconds,
    }

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("utf-8")

    sig = hmac.new(
        JWT_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).digest()

    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")

    return f"{payload_b64}.{sig_b64}"


# ---- BLACKLIST ----

def is_token_blacklisted(token: str) -> bool:
    resp = blacklist_table.get_item(Key={"token": token})
    return "Item" in resp


def blacklist_token(token: str):
    """
    Zapisujemy token do czarnej listy z TTL.
    TTL musi być kolumną 'ttl' w DynamoDB z włączonym Time-to-Live.
    """
    payload = verify_token_no_blacklist(token)
    if not payload:
        exp = int(time.time()) + 3600
    else:
        exp = payload["exp"]

    blacklist_table.put_item(
        Item={
            "token": token,
            "ttl": exp
        }
    )


# ---- TOKEN VERIFICATION ----

def verify_token_no_blacklist(token: str):
    """Sprawdza token bez sprawdzania blacklist — używane przez logout"""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        return None

    expected_sig = hmac.new(
        JWT_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).digest()

    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode("utf-8")

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None

    # Base64 padding
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)

    try:
        payload_bytes = base64.urlsafe_b64decode(padded.encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    if payload.get("exp", 0) < int(time.time()):
        return None

    return payload


def verify_token(token: str):
    """Pełna weryfikacja — łącznie z blacklist"""
    if is_token_blacklisted(token):
        return None

    return verify_token_no_blacklist(token)


# ---- USER OPS ----

def register_user(email: str, password: str):
    if not email or not password:
        return {"error": "Email and password required"}

    resp = users_table.get_item(Key={"email": email})
    if "Item" in resp:
        return {"error": "User already exists"}

    hashed = hash_password(password)

    users_table.put_item(Item={
        "email": email,
        "password": hashed,
    })

    return {"message": "User registered successfully"}


def login_user(email: str, password: str):
    resp = users_table.get_item(Key={"email": email})
    item = resp.get("Item")

    if not item or not verify_password(password, item["password"]):
        return {"error": "Invalid credentials"}

    return {"token": create_token(email)}


def logout_user(token: str):
    """Dodaje token do czarnej listy"""
    blacklist_token(token)
    return {"message": "Logged out"}


def get_profile_from_token(token: str):
    payload = verify_token(token)
    if not payload:
        return None

    return {"email": payload["email"]}
