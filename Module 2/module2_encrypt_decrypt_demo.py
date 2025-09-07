#!/usr/bin/env python3
"""
Module 2: Encrypt/Decrypt Demo
Demonstrates BOTH symmetric (Fernet/AES) and asymmetric (RSA-OAEP) encryption.
Outputs to console AND writes ./evidence.txt with:
- keys used
- inputs
- outputs
"""

from base64 import b64encode
from datetime import datetime
from textwrap import shorten

# --- Symmetric (Fernet/AES) ---
from cryptography.fernet import Fernet

# --- Asymmetric (RSA) ---
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def divider(title: str) -> str:
    line = "=" * 78
    return f"\n{line}\n{title}\n{line}\n"


def main():
    # Change this message if you want a custom plaintext demo
    plaintext = "Meet me at 10:30 by the library steps."

    out_lines = []
    out_lines.append(divider("INPUT"))
    out_lines.append(f"Plaintext: {plaintext}")

    # ----------------------------------------------------------------------
    # 1) SYMMETRIC ENCRYPTION (Fernet -> AES + HMAC; key shared)
    # ----------------------------------------------------------------------
    out_lines.append(divider("SYMMETRIC (Fernet)"))

    sym_key = Fernet.generate_key()           # base64-encoded 32-byte key
    fernet = Fernet(sym_key)

    sym_ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
    sym_decrypted = fernet.decrypt(sym_ciphertext).decode("utf-8")

    out_lines.append(f"Symmetric Key (Fernet, base64): {sym_key.decode()}")
    out_lines.append(f"Ciphertext (base64): {sym_ciphertext.decode()}")
    out_lines.append(f"Decrypted: {sym_decrypted}")

    # ----------------------------------------------------------------------
    # 2) ASYMMETRIC ENCRYPTION (RSA-OAEP with SHA-256; public/private pair)
    # ----------------------------------------------------------------------
    out_lines.append(divider("ASYMMETRIC (RSA-OAEP)"))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # demo only
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    rsa_ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    rsa_decrypted = private_key.decrypt(
        rsa_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ).decode("utf-8")

    out_lines.append(
        "Public Key (PEM, first 120 chars): "
        + shorten(pem_public.decode().replace("\n", "\\n"), width=120, placeholder="...")
    )
    out_lines.append(
        "Private Key (PEM, first 120 chars): "
        + shorten(pem_private.decode().replace("\n", "\\n"), width=120, placeholder="...")
    )
    out_lines.append("Ciphertext (RSA, base64): " + b64encode(rsa_ciphertext).decode())
    out_lines.append(f"Decrypted: {rsa_decrypted}")

    # ----------------------------------------------------------------------
    # Write evidence file (assignment requires keys/inputs/outputs)
    # ----------------------------------------------------------------------
    out_lines.append(divider("NOTES"))
    out_lines.append("• Symmetric: Fernet key is base64-encoded 32 bytes (AES + HMAC).")
    out_lines.append("• Asymmetric: RSA-2048 with OAEP(SHA-256). Encrypt w/ public, decrypt w/ private.")
    out_lines.append(f"Generated at: {datetime.now().isoformat(timespec='seconds')}")

    print("\n".join(out_lines))

    with open("evidence.txt", "w", encoding="utf-8") as f_out:
        f_out.write("\n".join(out_lines))

    with open("rsa_public.pem", "wb") as f_pub:
        f_pub.write(pem_public)
    with open("rsa_private.pem", "wb") as f_pri:
        f_pri.write(pem_private)


if __name__ == "__main__":
    main()
