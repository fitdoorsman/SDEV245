# Cryptographic Failures (Java)

### Vulnerability
Passwords were hashed with **MD5** (fast, unsalted), which is unsuitable for password storage.

### Fix
Use **PBKDF2-HMAC-SHA256** with a **random per-password salt** and **high iteration count** (120k). Verify using constant-time comparison.

### Why it works
Slow, salted derivation thwarts brute-force and rainbow-table attacks; constant-time compare prevents timing leaks.

### OWASP Reference
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
