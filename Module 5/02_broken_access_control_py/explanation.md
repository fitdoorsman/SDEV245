# Broken Access Control (Python)

### Vulnerability
`GET /account/<user_id>` returns a user record based only on the path parameter. There is **no authentication or authorization**.

### Why it's vulnerable
An attacker can change the `user_id` in the URL to access someone else’s account data. This is OWASP A01: Broken Access Control.

### Fix
- Require authentication with `@login_required`.
- Add an **ownership check** (`current_user.id == user_id`), with optional admin override.
- Return proper errors (`403` when not authorized, `404` when the record doesn't exist).

### Why the fix works
Authentication verifies identity; the authorization/ownership check ensures users can **only access their own data**.

### OWASP Reference
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
