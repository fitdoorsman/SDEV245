# Server-Side Request Forgery (SSRF)

### Vulnerability
Fetching an arbitrary user-supplied URL allows attackers to reach internal network addresses (metadata, internal APIs) or perform SSRF attacks.

### Fix
- Enforce **allow-list** of hosts and schemes.
- Block private/loopback IPs.
- Disable redirects and set timeouts.
- Prefer a proxy or resolver that enforces policies.

### Why it works
Limits outbound requests to known safe destinations, preventing access to internal resources.

### OWASP Reference
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
