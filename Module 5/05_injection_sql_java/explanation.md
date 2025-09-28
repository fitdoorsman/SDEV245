# Injection (SQL) — Java

### Vulnerability
The query concatenates user input:  
`"SELECT * FROM users WHERE username = '" + username + "'"`

### Why it's vulnerable
Attackers can inject SQL (e.g., `foo' OR '1'='1`) to bypass logic or exfiltrate data.

### Fix
Use a **parameterized query (PreparedStatement)** with placeholders (`?`) and bind values.

### Why it works
The database treats user input as data, not executable SQL, preventing injection.

### OWASP Reference
https://owasp.org/Top10/A03_2021-Injection/
