# Injection (NoSQL) — Node/MongoDB

### Vulnerability
The filter uses unvalidated `req.query.username` directly, allowing payloads like `{"$ne": null}`.

### Why it's vulnerable
MongoDB treats `$ne`, `$gt`, etc. as operators. If injected, the query can match unintended records or bypass checks.

### Fix
- **Validate/sanitize** input as a simple string.
- Use `{ username: { $eq: value } }` to force equality.
- Return 400 on invalid input.

### Why it works
Disallows operator characters and ensures the filter stays a literal comparison, preventing NoSQL operator injection.

### OWASP Reference
https://owasp.org/Top10/A03_2021-Injection/
