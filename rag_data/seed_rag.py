import json
import os

DEFAULT_KNOWLEDGE = [
    {
        "id": "A01:2021 / CWE-693",
        "name": "Security Misconfiguration & Missing Headers",
        "description": "Failure to implement security hardening options or essential browser protection headers like CSP, HSTS, and X-Frame-Options.",
        "remediation": "Add Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options headers. Ensure server environment files (.env) and source control files (.git) are never exposed via HTTP."
    },
    {
        "id": "A03:2021 / CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "description": "User-supplied input is included in response output without adequate validation or context-aware encoding, permitting client script execution.",
        "remediation": "Sanitize and context-encode all dynamic output rendered in templates or HTML elements using library utilities (e.g., html.escape in Python or DOMPurify in JS)."
    },
    {
        "id": "A03:2021 / CWE-89",
        "name": "SQL Injection",
        "description": "Untrusted user data is concatenated directly into SQL command strings, altering query logic.",
        "remediation": "Always use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) frameworks instead of string concatenation."
    },
    {
        "id": "A07:2021 / CWE-287",
        "name": "Broken Authentication & Cookie Flags",
        "description": "Session identifiers or tokens transmitted over plain channels or exposed to client-side scripts due to missing cookie security attributes.",
        "remediation": "Set HttpOnly, Secure, and SameSite=Lax/Strict flags on all session cookies. Rotate tokens upon authentication status changes."
    }
]

def ensure_rag_data_exists(target_path: str = "rag_data/owasp_cwe_knowledge.json"):
    """
    Ensures that the RAG data file exists. If missing, automatically creates
    the directory structure and writes the default OWASP/CWE JSON data.
    """
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    
    if not os.path.exists(target_path):
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_KNOWLEDGE, f, indent=2)
        print(f"✅ Successfully seeded knowledge base at {target_path}")
    else:
        print(f"ℹ️ Knowledge base already exists at {target_path}")

if __name__ == "__main__":
    ensure_rag_data_exists()