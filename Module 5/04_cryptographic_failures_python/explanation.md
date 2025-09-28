# Cryptographic Failures (Python)

### Vulnerability
Passwords were hashed using **SHA1** with no salt.

### Fix
Replace with **PBKDF2-HMAC-SHA256** + random salt (16 bytes) + ~120k iterations and constant-time verification.

### Why it works
Unique salted hashes defeat rainbow tables; the high iteration count slows brute-force; constant-time comparison mitigates timing attacks.

### OWASP Reference
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
