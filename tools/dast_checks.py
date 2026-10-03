import httpx
import time

def run_dast_scan(target_url: str, authorized: bool, log_callback=None) -> dict:
    if not authorized:
        return {"error": "DAST blocked: Target authorization checkbox not confirmed by user."}

    results = {
        "xss": [],
        "sqli": [],
        "misconfigs": [],
        "auth_signals": []
    }

    def audit_log(msg):
        if log_callback:
            log_callback(msg)

    client = httpx.Client(timeout=10.0, follow_redirects=True, headers={"User-Agent": "CyberSage-Agentic-Scanner/1.0"})

    # Check 1: Security Misconfigurations & Headers
    audit_log(f"[DAST] Checking security headers on {target_url}...")
    try:
        res = client.get(target_url)
        headers = res.headers
        missing = []
        for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
            if header not in headers:
                missing.append(header)
        if missing:
            results["misconfigs"].append({
                "issue": "Missing Security Headers",
                "details": f"Missing HTTP Headers: {', '.join(missing)}",
                "severity": "Medium",
                "cwe": "CWE-693"
            })
    except Exception as e:
        audit_log(f"[DAST Warning] Header check failed: {str(e)}")

    # Check 2: XSS Reflection Check
    audit_log("[DAST] Testing safe reflected XSS payload...")
    xss_payload = "<script>alert('scan-marker')</script>"
    try:
        res = client.get(target_url, params={"q": xss_payload, "search": xss_payload})
        if xss_payload in res.text:
            results["xss"].append({
                "issue": "Reflected Cross-Site Scripting (XSS)",
                "details": "Unescaped search payload detected in response body.",
                "severity": "High",
                "cwe": "CWE-79"
            })
    except Exception as e:
        audit_log(f"[DAST Warning] XSS check failed: {str(e)}")

    # Check 3: SQLi Detection (Safe Error Probe)
    audit_log("[DAST] Probing for SQL injection error signatures...")
    sqli_probe = "' OR '1'='1"
    try:
        res = client.get(target_url, params={"id": sqli_probe})
        errors = ["SQL syntax", "mysql_fetch", "ORA-00933", "SQLite3::query", "PostgreSQL error"]
        if any(err.lower() in res.text.lower() for err in errors):
            results["sqli"].append({
                "issue": "SQL Injection Signature Detected",
                "details": "Database error message reflected in HTTP response body.",
                "severity": "Critical",
                "cwe": "CWE-89"
            })
    except Exception as e:
        audit_log(f"[DAST Warning] SQLi check failed: {str(e)}")

    return results