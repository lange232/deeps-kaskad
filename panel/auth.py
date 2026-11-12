"""Authentication primitives for the panel.

Kept free of FastAPI and the database so the logic can be unit tested:
password hashing, email and password validation, and the signed session
cookie. The panel wraps these with request handling and role checks.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

PBKDF2_ITERATIONS = 310000
MIN_PASSWORD = 12
SESSION_TTL = 12 * 3600
ADMIN_LOGIN = "admin"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    """pbkdf2$<iterations>$<salt>$<hash>, one salt per password."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${_b64e(salt)}${_b64e(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def normalize_email(value: str) -> str:
    return value.strip().lower()


def email_error(email: str) -> str | None:
    if not email:
        return "email is required"
    if len(email) > 254:
        return "email is too long"
    if not EMAIL_RE.match(email):
        return "invalid email address"
    return None


def password_error(password: str, who: str = "password") -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"{who} must be at least {MIN_PASSWORD} characters"
    return None


def sign(payload: bytes, secret: str) -> str:
    return base64.urlsafe_b64encode(
        hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    ).decode()


def make_session(secret: str, role: str, uid: int = 0, tv: int = 0, ttl: int = SESSION_TTL) -> str:
    payload = json.dumps(
        {
            "role": role,
            "uid": uid,
            "tv": tv,
            "jti": secrets.token_urlsafe(16),
            "exp": int(time.time()) + ttl,
        }
    ).encode()
    return base64.urlsafe_b64encode(payload).decode() + "." + sign(payload, secret)


def session_data(secret: str, token: str | None) -> dict | None:
    """Returns the session payload, or None for a missing, forged or expired one."""
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    try:
        payload = base64.urlsafe_b64decode(body.encode())
    except Exception:
        return None
    if not hmac.compare_digest(sig, sign(payload, secret)):
        return None
    try:
        data = json.loads(payload)
        if data["exp"] <= time.time():
            return None
        if data.get("role") not in ("admin", "user"):
            return None
        return data
    except Exception:
        return None
