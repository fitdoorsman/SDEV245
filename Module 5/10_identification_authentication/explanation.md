# Identification & Authentication Failures

### Vulnerability
Comparing plaintext passwords (or storing raw passwords) is insecure and may leak credentials if storage is compromised.

### Fix
- Store only strong password hashes (salted, slow KDF like PBKDF2/bcrypt/Argon2).
- Verify using the appropriate verify routine (constant-time compare).
- Add multi-factor authentication and session protections where applicable.

### Why it works
Slow, salted hashes protect against offline brute-force; constant-time comparison prevents timing leaks.

### OWASP Reference
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
