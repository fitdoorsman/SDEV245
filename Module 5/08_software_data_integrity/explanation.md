# Software & Data Integrity Failures

### Vulnerability
Loading remote JS without verification allows the content to be tampered with and execute malicious code in your site.

### Fix
- Self-host a pinned, audited version of third-party libraries, **or**
- Use **Subresource Integrity (SRI)** with exact version and hash + `crossorigin="anonymous"` for CDN assets.

### Why it works
SRI ensures the browser refuses to execute a script whose hash doesn't match the expected, preventing supply-chain tampering.

### OWASP Reference
https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
