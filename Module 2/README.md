# Module 2: Encrypt/Decrypt Demo

This project is for **Module 2: Assignment – Encrypt/Decrypt Demo**.  
It demonstrates encrypting and decrypting a short message using **both** symmetric and asymmetric encryption methods.

- **Symmetric:** Fernet (AES + HMAC) using the same key for encrypt/decrypt  
- **Asymmetric:** RSA-2048 with OAEP (SHA-256) using a public/private key pair  

Running the script generates **`evidence.txt`** which shows:  
- Keys used  
- Plaintext input  
- Ciphertexts  
- Decrypted outputs  

---

## Files

- `module2_encrypt_decrypt_demo.py` – main program
- `requirements.txt` – dependency list
- *(generated after running)*  
  - `evidence.txt` – shows inputs, keys, outputs (submit/screenshot this file)  
  - `rsa_public.pem` – RSA public key  
  - `rsa_private.pem` – RSA private key  

---

## How to Run

```bash
# 1) Create virtual environment
python -m venv venv

# 2) Activate it
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate

# 3) Install required library
pip install -r requirements.txt

# 4) Run the demo
python module2_encrypt_decrypt_demo.py
