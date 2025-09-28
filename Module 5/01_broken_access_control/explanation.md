# Broken Access Control

### Vulnerability
The endpoint `GET /profile/:userId` returns a user object based only on the path parameter. There is no authentication or authorization check.

### Why the original code is vulnerable
An attacker (or any authenticated user) could change the `userId` in the URL and retrieve another user's profile. This is Broken Access Control (OWASP A01).

### Fix applied
- Added a lightweight authentication guard (`authenticateUser`) to require a logged-in user.
- Enforced an ownership check so a user can only access their own profile (`req.user.id === req.params.userId`).
- Added basic error handling (404 for missing user, 403 for denied access).

### Why the fix works
Authentication prevents anonymous access; the ownership/authorization check prevents users from accessing other users' data by guessing or enumerating IDs. Error handling avoids exposing internal errors and avoids leaking unnecessary information.

### OWASP reference
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
