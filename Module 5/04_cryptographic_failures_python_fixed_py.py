# fixed_py.py
import os, base64, hashlib, hmac

ITERATIONS = 120_000
KEY_LEN = 32  # 256-bit

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, dklen=KEY_LEN)
    return f"pbkdf2${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def verify_password(password: str, stored: str) -> bool:
    _, iters, salt_b64, hash_b64 = stored.split('$')
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, int(iters), dklen=len(expected))
    return hmac.compare_digest(actual, expected)
