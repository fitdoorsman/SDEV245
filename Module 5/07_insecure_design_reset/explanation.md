# Insecure Design — Password Reset

### Vulnerability
The original endpoint directly accepted an email + new password and updated the password without verifying identity, allowing account takeover.

### Fix
- Use a **time-limited, single-use token** sent out-of-band (email).
- Rate-limit sensitive endpoints.
- Always return the same response for request-reset to avoid account enumeration.
- Invalidate token after use and require strong password policy + secure hashing.

### Why it works
Token + email proves possession, rate-limiting reduces abuse, and one-time tokens avoid replay attacks.

### OWASP Reference
https://owasp.org/Top10/A04_2021-Insecure_Design/
