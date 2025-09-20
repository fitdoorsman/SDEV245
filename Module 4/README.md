# SDEV245 – Module 4 Midterm: Build a Secure Data Transmission App with Hashing and Encryption

**Author:** Jason Hollin  
**Date:** September 2025  
**Course:** Secure Software Development  

---

## Description
This project demonstrates secure hashing, encryption, and integrity verification with a simple **user login and role-based access control** as required for Module 4 of SDEV245. It includes:

1. **User Login & Roles** – PBKDF2-HMAC-SHA256 password hashes; roles: `admin`, `user` (admins can add users)  
2. **SHA-256 Hashing** – hash plain text and file contents  
3. **AES-GCM (Symmetric Encryption)** – encrypt/decrypt text or files using PBKDF2-derived keys (with random salt + iterations)  
4. **Integrity Verification** – compare SHA-256 before encryption vs after decryption  

---

## Requirements
- Python **3.9+**  
- One package to install:  
  ```bash
  pip install cryptography
