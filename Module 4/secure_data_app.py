#!/usr/bin/env python3
"""
SDEV245 – Module 4 Midterm: Build a Secure Data Transmission App with Hashing and Encryption
Author: Jason Hollin
Date: September 2025

Features:
  • User login & role-based access (users.json with PBKDF2 password hashes)
  • SHA-256 hashing of text or files (integrity)
  • AES-256-GCM encryption/decryption with PBKDF2 key derivation (confidentiality + AEAD)
  • Integrity verification by comparing pre/post SHA-256 hashes from the encrypted bundle
"""

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional, Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------
# Configuration
# ---------------------------
USERS_DB = "users.json"           # persistent user store (JSON)
PWD_SALT_LEN = 16                 # 128-bit salt for password storage
KDF_ITERS = 200_000               # PBKDF2 iterations
ENC_SALT_LEN = 16                 # 128-bit salt for encryption KDF
NONCE_LEN = 12                    # 96-bit nonce for AES-GCM
KEY_LEN = 32                      # 256-bit AES key


# ---------------------------
# Utility helpers
# ---------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def read_bytes(text: Optional[str], path: Optional[str]) -> bytes:
    if (text is None) == (path is None):
        raise ValueError("Provide exactly one of --text or --in")
    if text is not None:
        return text.encode("utf-8")
    with open(path, "rb") as f:
        return f.read()


def write_bytes_if_requested(data: bytes, path: Optional[str]) -> None:
    if path:
        with open(path, "wb") as f:
            f.write(data)


def write_text_if_requested(text: str, path: Optional[str]) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


# ---------------------------
# User store (password hashing PBKDF2)
# ---------------------------
def load_users() -> Dict[str, Any]:
    if not os.path.exists(USERS_DB):
        return {"users": {}}
    with open(USERS_DB, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(db: Dict[str, Any]) -> None:
    with open(USERS_DB, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def kdf_pbkdf2_sha256(password: str, salt: bytes, length: int = KEY_LEN, iterations: int = KDF_ITERS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))


def create_user(username: str, password: str, role: str) -> None:
    if role not in ("admin", "user"):
        raise ValueError("role must be 'admin' or 'user'")
    db = load_users()
    if username in db["users"]:
        raise ValueError("user already exists")
    salt = os.urandom(PWD_SALT_LEN)
    pwd_hash = kdf_pbkdf2_sha256(password, salt, length=32)
    db["users"][username] = {
        "role": role,
        "salt": b64e(salt),
        "iterations": KDF_ITERS,
        "pwd_hash_b64": b64e(pwd_hash),
    }
    save_users(db)


def verify_user(username: str, password: str) -> Dict[str, Any]:
    db = load_users()
    user = db["users"].get(username)
    if not user:
        raise ValueError("invalid username or password")
    salt = b64d(user["salt"])
    expected = b64d(user["pwd_hash_b64"])
    pwd_hash = kdf_pbkdf2_sha256(password, salt, length=len(expected), iterations=user["iterations"])
    if pwd_hash != expected:
        raise ValueError("invalid username or password")
    return user  # includes role


def require_admin(auth_user: str, auth_pass: str) -> None:
    user = verify_user(auth_user, auth_pass)
    if user["role"] != "admin":
        raise PermissionError("admin role required")


def require_login(auth_user: str, auth_pass: str) -> Dict[str, Any]:
    return verify_user(auth_user, auth_pass)  # returns user record


# ---------------------------
# Hashing (Integrity)
# ---------------------------
def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


# ---------------------------
# Encryption / Decryption (AES-GCM with PBKDF2 key)
# ---------------------------
@dataclass
class Bundle:
    scheme: str
    kdf: str
    iterations: int
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str
    sha256_hex_before: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2)

    @staticmethod
    def from_json(s: str) -> "Bundle":
        obj = json.loads(s)
        required = {"scheme", "kdf", "iterations", "salt_b64", "nonce_b64", "ciphertext_b64", "sha256_hex_before"}
        if not required.issubset(obj.keys()):
            raise ValueError("Invalid bundle JSON")
        return Bundle(**obj)


def derive_enc_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERS) -> bytes:
    return kdf_pbkdf2_sha256(passphrase, salt, length=KEY_LEN, iterations=iterations)


def encrypt_bytes(plaintext: bytes, passphrase: str) -> Bundle:
    salt = os.urandom(ENC_SALT_LEN)
    key = derive_enc_key(passphrase, salt)
    nonce = os.urandom(NONCE_LEN)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    return Bundle(
        scheme="AES-256-GCM",
        kdf="PBKDF2-HMAC-SHA256",
        iterations=KDF_ITERS,
        salt_b64=b64e(salt),
        nonce_b64=b64e(nonce),
        ciphertext_b64=b64e(ciphertext),
        sha256_hex_before=sha256_hex(plaintext),
    )


def decrypt_bundle(bundle: Bundle, passphrase: str) -> bytes:
    salt = b64d(bundle.salt_b64)
    nonce = b64d(bundle.nonce_b64)
    ciphertext = b64d(bundle.ciphertext_b64)
    key = derive_enc_key(passphrase, salt, bundle.iterations)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------
# CLI command handlers
# ---------------------------
def cmd_init_admin(a: argparse.Namespace) -> int:
    if os.path.exists(USERS_DB) and load_users()["users"]:
        print("User store already initialized.", file=sys.stderr)
        return 1
    create_user(a.username, a.password, "admin")
    print(f"Admin user '{a.username}' created.")
    return 0


def cmd_add_user(a: argparse.Namespace) -> int:
    try:
        require_admin(a.auth_user, a.auth_pass)
        create_user(a.username, a.password, a.role)
        print(f"User '{a.username}' created with role '{a.role}'.")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


def cmd_hash(a: argparse.Namespace) -> int:
    try:
        require_login(a.auth_user, a.auth_pass)
        data = read_bytes(a.text, a.input)
        h = sha256_hex(data)
        print(f"SHA-256: {h}")
        write_text_if_requested(h + "\n", a.out)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


def cmd_encrypt(a: argparse.Namespace) -> int:
    try:
        require_login(a.auth_user, a.auth_pass)
        data = read_bytes(a.text, a.input)
        bundle = encrypt_bytes(data, a.passphrase)
        out_json = bundle.to_json()
        if a.out:
            write_text_if_requested(out_json, a.out)
            print(f"Encrypted bundle written to {a.out}")
        else:
            print(out_json)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


def cmd_decrypt(a: argparse.Namespace) -> int:
    try:
        require_login(a.auth_user, a.auth_pass)
        with open(a.input, "r", encoding="utf-8") as f:
            bundle = Bundle.from_json(f.read())
        plaintext = decrypt_bundle(bundle, a.passphrase)
        if a.out:
            write_bytes_if_requested(plaintext, a.out)
            print(f"Decrypted plaintext written to {a.out}")
        else:
            try:
                print(plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                # binary; print base64 for safety
                print(b64e(plaintext))
        return 0
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        return 3


def cmd_verify(a: argparse.Namespace) -> int:
    try:
        require_login(a.auth_user, a.auth_pass)
        with open(a.input, "r", encoding="utf-8") as f:
            bundle = Bundle.from_json(f.read())
        plaintext = decrypt_bundle(bundle, a.passphrase)
        after = sha256_hex(plaintext)
        ok = (after == bundle.sha256_hex_before)
        print(f"Original SHA-256 (stored): {bundle.sha256_hex_before}")
        print(f"Decrypted SHA-256       : {after}")
        print("Integrity verified ✅" if ok else "Integrity check FAILED ❌")
        return 0 if ok else 4
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 3


# ---------------------------
# Parser
# ---------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 4: Secure Data Transmission (login/roles, SHA-256, AES-256-GCM, integrity verification)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # init-admin
    pa = sub.add_parser("init-admin", help="Initialize the user store with the first admin.")
    pa.add_argument("--username", required=True)
    pa.add_argument("--password", required=True)
    pa.set_defaults(func=cmd_init_admin)

    # add-user (admin only)
    pu = sub.add_parser("add-user", help="Create a new user (admin only).")
    pu.add_argument("--auth-user", required=True)
    pu.add_argument("--auth-pass", required=True)
    pu.add_argument("--username", required=True)
    pu.add_argument("--password", required=True)
    pu.add_argument("--role", required=True, choices=["admin", "user"])
    pu.set_defaults(func=cmd_add_user)

    # shared auth options
    def add_auth_args(x: argparse.ArgumentParser):
        x.add_argument("--auth-user", required=True)
        x.add_argument("--auth-pass", required=True)

    # hash
    ph = sub.add_parser("hash", help="Compute SHA-256 of text or file (any role).")
    add_auth_args(ph)
    ph.add_argument("--text")
    ph.add_argument("--in", dest="input")
    ph.add_argument("--out")
    ph.set_defaults(func=cmd_hash)

    # encrypt
    pe = sub.add_parser("encrypt", help="Encrypt text or file with AES-256-GCM (any role).")
    add_auth_args(pe)
    pe.add_argument("--text")
    pe.add_argument("--in", dest="input")
    pe.add_argument("--passphrase", required=True)
    pe.add_argument("--out")
    pe.set_defaults(func=cmd_encrypt)

    # decrypt
    pd = sub.add_parser("decrypt", help="Decrypt a JSON bundle (any role).")
    add_auth_args(pd)
    pd.add_argument("--in", dest="input", required=True)
    pd.add_argument("--passphrase", required=True)
    pd.add_argument("--out")
    pd.set_defaults(func=cmd_decrypt)

    # verify
    pv = sub.add_parser("verify", help="Decrypt and verify integrity (any role).")
    add_auth_args(pv)
    pv.add_argument("--in", dest="input", required=True)
    pv.add_argument("--passphrase", required=True)
    pv.set_defaults(func=cmd_verify)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
