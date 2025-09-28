# vulnerable_py.py
import hashlib

def hash_password(password):
    # Insecure: SHA1 without salt
    return hashlib.sha1(password.encode()).hexdigest()
