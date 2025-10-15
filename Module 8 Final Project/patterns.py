"""
Regex patterns for common secrets.
Each tuple: (Pattern Name, Regular Expression)
"""
PATTERNS = [
    ("AWS Access Key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key", r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
    ("GitHub Token", r"\bghp_[0-9A-Za-z]{36}\b"),
    ("Generic API Key", r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{32,45}['\"]?"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Private Key (BEGIN)", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Hardcoded Password", r"(?i)\bpass(word)?\b\s*[:=]\s*['\"][^'\"\n]{4,}['\"]"),
    ("Basic Auth in URL", r"\b[a-zA-Z0-9._%+\-]+:[^@\s]{4,}@[^/\s]+"),
    ("Azure Storage Key", r"(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/=]{40,}"),
    ("Stripe Secret Key", r"\bsk_(live|test)_[0-9a-zA-Z]{24,}\b"),
]
