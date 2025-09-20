# SDEV245 – Module 4 Midterm: Build a Secure Data Transmission App with Hashing and Encryption

**Author:** Jason Hollin  
**Date:** September 2025  
**Course:** Secure Software Development  

---

## Description
This project demonstrates secure hashing, encryption, and integrity verification with a simple **user login and role-based access control** as required for Module 4 of SDEV245. It includes:

1. **User Login & Roles**  
   - Users stored with PBKDF2-HMAC-SHA256 password hashes  
   - Roles: `admin`, `user` (admins can add users)  

2. **SHA-256 Hashing**  
   - Hash plain text strings  
   - Hash file contents  

3. **AES-GCM (Symmetric Encryption)**  
   - Encrypt text or files using PBKDF2-derived keys (with random salt + iterations)  
   - Decrypt securely to recover the original content  

4. **Integrity Verification**  
   - Compute SHA-256 hash before encryption  
   - Decrypt and recompute hash  
   - Compare to confirm integrity  

---

## Features
- User authentication with role-based restrictions  
- Passwords stored securely with salt and high iteration count  
- SHA-256 hashing for messages and files  
- AES-256-GCM encryption and decryption  
- Integrity verification with hash-before / hash-after comparison  

---

## Files
- `secure_data_app.py` → Main Python program  
- `README.md` → Documentation (this file)  
- `users.json` → **Generated** after running `init-admin` (stores user accounts)  
- `demo.txt` → **Generated** sample file for hashing/encryption (created during demo)  
- `secret_text.json` → **Generated** encrypted text bundle (output from encryption)  
- `secret_file.json` → **Generated** encrypted file bundle (optional output)  

---

## Usage Examples

### 1) Initialize admin user
```bash
python secure_data_app.py init-admin --username admin --password "AdminPass123!"
