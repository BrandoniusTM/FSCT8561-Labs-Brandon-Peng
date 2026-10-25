import hashlib
import hmac
import re
import secrets
import time

ITERATIONS = 350_000


def make_password_record(password):
    """Store a salted PBKDF2 hash, never the original password."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": ITERATIONS}


def check_password(password, record):
    try:
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(record["iterations"])
        )
        return hmac.compare_digest(actual, expected)
    except (KeyError, ValueError, TypeError):
        return False


def matching_totp_step(secret, code):
    """Return matching 30-second step or None. A step may only be used once."""
    import pyotp

    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    current_step = int(time.time() // 30)
    for step in (current_step - 1, current_step, current_step + 1):
        if hmac.compare_digest(code, totp.at(step * 30)):
            return step
    return None
