#!/usr/bin/env python3
"""
Course: SDEV245 - Secure Software Development
Module: 3
Assignment: Secure Hashing and Encryption
Author: Jason Hollin
Date: September 2025

File: crypto_app.py

Description:
------------
This program demonstrates secure hashing, simple substitution encryption,
and digital signatures as required for Module 3.

Features implemented:
1. SHA-256 hashing for both text strings and files
2. Caesar cipher for encrypting and decrypting text
3. RSA-based digital signature (sign and verify) using cryptography library

Usage Examples:
---------------
    # Hash text
    python crypto_app.py hash --text "Hello, Ivy Tech!"

    # Hash a file
    python crypto_app.py hash --file demo.txt

    # Encrypt and decrypt with Caesar cipher
    python crypto_app.py caesar --text "Attack at Dawn!" --shift 5 --mode enc
    python crypto_app.py caesar --text "Fyyfhp fy Ifbs!" --shift 5 --mode dec

    # Sign and verify message
    python crypto_app.py sign --message "Assignment demo"
"""

import argparse
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# -------------------- SHA-256 (text & file) -------------------- #
def sha256_text(s: str) -> str:
    """Return SHA-256 hex digest of a text string."""
    return hashlib.sha256(s.encode()).hexdigest()


def sha256_file(path: str) -> str:
    """Return SHA-256 hex digest of a file (streamed in chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# -------------------- Caesar cipher -------------------- #
def caesar(text: str, shift: int) -> str:
    """Shift alphabetic characters by 'shift' (wraps A-Z / a-z)."""
    out_chars = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out_chars.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out_chars.append(ch)
    return "".join(out_chars)


# -------------------- RSA sign / verify -------------------- #
def gen_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a 2048-bit RSA keypair."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def sign(priv: rsa.RSAPrivateKey, msg: str) -> bytes:
    """Sign message with RSA-PSS + SHA-256."""
    return priv.sign(
        msg.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(pub: rsa.RSAPublicKey, msg: str, sig: bytes) -> bool:
    """Verify RSA-PSS + SHA-256 signature. Return True/False."""
    try:
        pub.verify(
            sig,
            msg.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# -------------------- CLI -------------------- #
def main():
    parser = argparse.ArgumentParser(
        description="SHA-256 hashing, Caesar cipher, and RSA digital signature demo"
    )
    subs = parser.add_subparsers(dest="cmd", required=True)

    # hash subcommand
    p_hash = subs.add_parser("hash", help="Hash text or file with SHA-256")
    g = p_hash.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Text to hash")
    g.add_argument("--file", help="Path to file to hash")

    # caesar subcommand
    p_caesar = subs.add_parser("caesar", help="Encrypt/Decrypt with Caesar cipher")
    p_caesar.add_argument("--text", required=True, help="Text to process")
    p_caesar.add_argument("--shift", type=int, default=3, help="Shift amount (default 3)")
    p_caesar.add_argument("--mode", choices=["enc", "dec"], default="enc", help="enc or dec")

    # sign subcommand
    p_sign = subs.add_parser("sign", help="Sign message and verify signature")
    p_sign.add_argument("--message", required=True, help="Message to sign")

    args = parser.parse_args()

    if args.cmd == "hash":
        if args.text is not None:
            print(sha256_text(args.text))
        else:
            print(sha256_file(args.file))

    elif args.cmd == "caesar":
        shift = args.shift if args.mode == "enc" else -args.shift
        print(caesar(args.text, shift))

    elif args.cmd == "sign":
        priv, pub = gen_keys()
        sig = sign(priv, args.message)
        print("signature(hex):", sig.hex())
        print("verified:", verify(pub, args.message, sig))


if __name__ == "__main__":
    main()
