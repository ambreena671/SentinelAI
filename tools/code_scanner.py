import os
import re
import tempfile
import subprocess
import shutil
import json
from typing import Any, Dict, List, Tuple

MAX_CODE_CHARS = 300_000

RULES = [
    {
        "id": "hardcoded-secret",
        "pattern": re.compile(r'(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*["\'][^"\']{8,}["\']'),
        "issue": "Possible Hardcoded Secret",
        "category": "Secrets",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "attack_type": "Credential exposure / account or service abuse",
        "risk": "An exposed credential could be reused by someone who obtains the source code.",
        "remediation": "Move secrets to environment variables or a managed secret store and rotate any credential that was exposed.",
    },
    {
        "id": "sql-concat",
        "pattern": re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*(\+|\%s|\.format\(|f["\'])'),
        "issue": "Possible SQL Injection",
        "category": "Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "attack_type": "SQL injection",
        "risk": "Untrusted input may alter database query structure and could expose or modify database records.",
        "remediation": "Use parameterized queries/prepared statements or a safe ORM API. Do not concatenate untrusted input into SQL.",
    },
    {
        "id": "command-concat",
        "pattern": re.compile(r'(?i)\b(os\.system|subprocess\.(run|Popen|call)|child_process\.(exec|execSync)|shell=True)\b'),
        "issue": "Possible OS Command Injection Sink",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "attack_type": "OS command injection",
        "risk": "If attacker-controlled input reaches the command, the application could execute unintended operating-system operations.",
        "remediation": "Avoid shell execution where possible. Use safe argument arrays, strict allowlists, and never pass untrusted strings to a shell.",
    },
    {
        "id": "dangerous-eval",
        "pattern": re.compile(r'(?i)\b(eval|exec|Function)\s*\('),
        "issue": "Dynamic Code Execution",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "attack_type": "Code injection",
        "risk": "If untrusted input reaches the dynamic execution function, arbitrary application code may be executed.",
        "remediation": "Remove dynamic execution. Use structured parsing, explicit dispatch, or a strict allowlist of permitted operations.",
    },
    {
        "id": "xss-html",
        "pattern": re.compile(r'(?i)(innerHTML\s*=|dangerouslySetInnerHTML|Markup\(|mark_safe\()'),
        "issue": "Possible Cross-Site Scripting Sink",
        "category": "Client-side injection",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "attack_type": "Cross-site scripting (XSS)",
        "risk": "If attacker-controlled content reaches an unsafe HTML sink, browser-side script execution may become possible.",
        "remediation": "Prefer safe text rendering. Context-encode output and sanitize HTML with a well-maintained sanitizer when HTML is genuinely required.",
    },
    {
        "id": "path-traversal",
        "pattern": re.compile(r'(?i)(open\(|readFile\(|readFileSync\(|send_file\(|sendFile\().*(request|req\.|params|query|input|filename)'),
        "issue": "Possible Path Traversal",
        "category": "File access",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "attack_type": "Path traversal / unauthorized file access",
        "risk": "Unvalidated file paths can allow access outside the intended directory.",
        "remediation": "Use fixed directories, canonicalize paths, reject unexpected path components, and enforce an allowlist of permitted files.",
    },
    {
        "id": "ssrf",
        "pattern": re.compile(r'(?i)(requests\.(get|post|put|delete)|httpx\.(get|post)|fetch\(|axios\.(get|post)|urllib\.request).*(request|req\.|url|input)'),
        "issue": "Possible Server-Side Request Forgery (SSRF)",
        "category": "Server-side request",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "attack_type": "SSRF",
        "risk": "If a user controls the destination URL, the server may be induced to make unintended outbound requests.",
        "remediation": "Use destination allowlists, block private/link-local address ranges where appropriate, and validate URLs before making server-side requests.",
    },
    {
        "id": "weak-hash",
        "pattern": re.compile(r'(?i)\b(md5|sha1)\s*\('),
        "issue": "Weak Cryptographic Hash",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "attack_type": "Cryptographic weakness",
        "risk": "Weak hashes can be unsuitable for password storage or security-sensitive integrity purposes.",
        "remediation": "For passwords, use a dedicated password hashing function such as Argon2id, scrypt, or bcrypt. For integrity use cases, choose a modern construction appropriate to the purpose.",
    },
    {
        "id": "debug-enabled",
        "pattern": re.compile(r'(?i)\b(debug\s*=\s*True|app\.run\(.*debug\s*=\s*True)'),
        "issue": "Debug Mode Enabled",
        "category": "Security misconfiguration",
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "owasp": "A05:2021 - Security Misconfiguration",
        "attack_type": "Information disclosure / misconfiguration",
        "risk": "Debug features can disclose internal details and should not be enabled in production.",
        "remediation": "Disable debug mode in production and configure error handling to avoid exposing stack traces or internal configuration.",
    },
    {
        "id": "cors-wildcard",
        "pattern": re.compile(r'(?i)(Access-Control-Allow-Origin|cors).{0,80}["\']\*["\']'),
        "issue": "Permissive CORS Configuration",
        "category": "Security misconfiguration",
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "attack_type": "Cross-origin abuse",
        "risk": "Overly broad cross-origin policy can expose browser-accessible resources to untrusted origins depending on the endpoint and credentials policy.",
        "remediation": "Allow only trusted origins and use the narrowest CORS policy required by the application.",
    },
]

def _mask_secret(text: str) -> str:
    if len(text) <= 10:
        return "*" * len(text)
    return text[:4] + "*" * max(4, len(text) - 8) + text[-4:]

def _evidence(line: str, secret=False) -> str:
    if not secret:
        return line.strip()[:500]
    return re.sub(
        r'(["\'])([^"\']{8,})(\1)',
        lambda m: m.group(1) + _mask_secret(m.group(2)) + m.group(1),
        line.strip()[:500],
    )

def heuristic_scan(code: str, file_name: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "source": "CyberSage static heuristics",
                    "rule_id": rule["id"],
                    "issue": rule["issue"],
                    "category": rule["category"],
                    "file_path": file_name,
                    "line_start": lineno,
                    "line_end": lineno,
                    "severity": rule["severity"],
                    "confidence": "Potential - review context",
                    "message": f"Potential {rule['issue'].lower()} detected.",
                    "cwe": rule["cwe"],
                    "owasp": rule["owasp"],
                    "attack_type": rule["attack_type"],
                    "risk": rule["risk"],
                    "evidence": _evidence(line, rule["id"] == "hardcoded-secret"),
                    "remediation": rule["remediation"],
                })
    return findings

def semgrep_scan(code: str, file_name: str) -> List[Dict[str, Any]]:
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return []
    suffix = os.path.splitext(file_name)[1] or ".txt"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        cmd = [
            semgrep_bin, "scan", "--config=p/owasp-top-ten",
            "--json", "--quiet", "--metrics=off", tmp_path
        ]
        process = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        if process.returncode not in (0, 1) or not process.stdout.strip():
            return []
        data = json.loads(process.stdout)
        results = []
        for match in data.get("results", []):
            extra = match.get("extra", {})
            meta = extra.get("metadata", {})
            cwe = meta.get("cwe", "CWE-Unknown")
            if isinstance(cwe, list):
                cwe = ", ".join(map(str, cwe))
            owasp = meta.get("owasp", "N/A")
            if isinstance(owasp, list):
                owasp = ", ".join(map(str, owasp))
            results.append({
                "source": "SAST (Semgrep)",
                "rule_id": match.get("check_id"),
                "issue": extra.get("message", match.get("check_id", "Semgrep finding")),
                "category": "Static analysis",
                "file_path": file_name,
                "line_start": match.get("start", {}).get("line"),
                "line_end": match.get("end", {}).get("line"),
                "severity": str(extra.get("severity", meta.get("severity", "WARNING"))).upper(),
                "confidence": meta.get("confidence", "Semgrep-detected"),
                "message": extra.get("message", "Potential security issue detected by Semgrep."),
                "cwe": cwe,
                "owasp": owasp,
                "attack_type": "See vulnerability classification",
                "risk": "Static analysis indicates a potentially security-relevant code pattern.",
                "evidence": extra.get("lines", ""),
                "remediation": meta.get("fix", "Review the Semgrep rule guidance and apply a safe coding pattern."),
            })
        return results
    except Exception:
        return []
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def scan_source_code(code: str, file_name: str = "source.txt") -> List[Dict[str, Any]]:
    if not code or not code.strip():
        return []
    if len(code) > MAX_CODE_CHARS:
        raise ValueError(f"Code is too large. Maximum supported size is {MAX_CODE_CHARS:,} characters.")

    heuristic = heuristic_scan(code, file_name)
    semgrep = semgrep_scan(code, file_name)

    # Deduplicate obvious overlaps by line + issue.
    seen: set[Tuple[Any, Any, Any]] = set()
    merged = []
    for item in semgrep + heuristic:
        key = (
            item.get("line_start"),
            item.get("cwe"),
            item.get("issue"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "WARNING": 2}
    merged.sort(key=lambda x: (severity_order.get(str(x.get("severity")).upper(), 9), x.get("line_start") or 0))
    return merged
