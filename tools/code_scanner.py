import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Tuple

MAX_CODE_CHARS = 300_000

# These are intentionally conservative source-code indicators. They report
# "potential" weaknesses rather than claiming exploitability.
RULES = [
    {
        "id": "hardcoded-secret",
        "pattern": re.compile(r'(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|token|access[_-]?token|private[_-]?key)\b\s*[:=]\s*[\"\'][^\"\']{8,}[\"\']'),
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
        "pattern": re.compile(r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*(?:\+|\.format\(|f[\"\']|%\s*\(|%s|String\.format)'),
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
        "id": "sql-execute-variable",
        "pattern": re.compile(r'(?i)\.(?:execute|executemany)\s*\(\s*(?:query|sql|statement)\s*\)'),
        "issue": "Database Query Uses a Dynamically Built Variable",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "attack_type": "Potential SQL injection",
        "risk": "A dynamically constructed SQL variable reaching execute() can be unsafe if user input was incorporated without parameterization.",
        "remediation": "Trace the query construction and use parameterized statements. This finding requires manual data-flow review.",
    },
    {
        "id": "command-exec",
        "pattern": re.compile(r'(?i)\b(os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|execSync)|Runtime\.getRuntime\(\)\.exec|shell=True)\b'),
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
        "pattern": re.compile(r'(?i)\b(?:eval|exec|Function|vm\.runIn(?:New)?Context)\s*\('),
        "issue": "Dynamic Code Execution",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "attack_type": "Code injection",
        "risk": "If untrusted input reaches the dynamic execution function, unintended application code may be executed.",
        "remediation": "Remove dynamic evaluation. Use structured parsing, explicit dispatch, or a strict allowlist of permitted operations.",
    },
    {
        "id": "xss-sink",
        "pattern": re.compile(r'(?i)(?:innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|Markup\(|mark_safe\(|render_template_string\s*\()'),
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
        "pattern": re.compile(r'(?i)(?:open\(|readFile\(|readFileSync\(|send_file\(|sendFile\(|fs\.createReadStream\().*(?:request|req\.|params|query|input|filename|path)'),
        "issue": "Possible Path Traversal",
        "category": "File access",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "attack_type": "Path traversal / unauthorized file access",
        "risk": "Unvalidated file paths can allow access outside the intended directory.",
        "remediation": "Canonicalize paths, enforce an allowlist, use a fixed base directory, and reject unsafe path components.",
    },
    {
        "id": "ssrf",
        "pattern": re.compile(r'(?i)(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post)|fetch\(|axios\.(?:get|post)|urllib\.request\.).*(?:request|req\.|url|input|target|callback)'),
        "issue": "Possible Server-Side Request Forgery (SSRF)",
        "category": "Server-side request",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "attack_type": "SSRF",
        "risk": "If a user controls the destination URL, the server may be induced to make unintended outbound requests.",
        "remediation": "Use destination allowlists, URL validation, and network-level restrictions where appropriate.",
    },
    {
        "id": "unsafe-deserialization",
        "pattern": re.compile(r'(?i)(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads?|ObjectInputStream\s*\()'),
        "issue": "Possible Unsafe Deserialization",
        "category": "Deserialization",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "attack_type": "Deserialization abuse / possible code execution",
        "risk": "Deserializing attacker-controlled data with unsafe mechanisms can create severe integrity or code-execution risks.",
        "remediation": "Avoid native object deserialization for untrusted data. Prefer safe data-only formats and strict schemas.",
    },
    {
        "id": "tls-disabled",
        "pattern": re.compile(r'(?i)(?:verify\s*=\s*False|ssl_verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE)'),
        "issue": "TLS Certificate Verification Disabled",
        "category": "Transport security",
        "severity": "HIGH",
        "cwe": "CWE-295",
        "owasp": "A02:2021 - Cryptographic Failures",
        "attack_type": "Man-in-the-middle / transport interception",
        "risk": "Disabling certificate verification can allow an attacker positioned on the network path to impersonate the remote service.",
        "remediation": "Keep certificate verification enabled and use a properly configured trust store.",
    },
    {
        "id": "weak-hash",
        "pattern": re.compile(r'(?i)\b(?:md5|sha1|hashlib\.md5|hashlib\.sha1)\s*\('),
        "issue": "Weak Cryptographic Hash",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "attack_type": "Cryptographic weakness",
        "risk": "Weak hashes can be unsuitable for password storage or security-sensitive integrity purposes.",
        "remediation": "For passwords, use Argon2id, scrypt, or bcrypt. For integrity, choose a modern construction appropriate to the use case.",
    },
    {
        "id": "insecure-password-hash",
        "pattern": re.compile(r'(?i)(?:password|passwd|pwd).{0,80}(?:md5|sha1|sha256)\s*\('),
        "issue": "Potentially Insecure Password Hashing",
        "category": "Authentication",
        "severity": "HIGH",
        "cwe": "CWE-916",
        "owasp": "A02:2021 - Cryptographic Failures",
        "attack_type": "Credential cracking / account compromise",
        "risk": "Fast general-purpose hashes are not designed for password storage and can make offline password guessing easier.",
        "remediation": "Use a dedicated password-hashing function such as Argon2id, scrypt, or bcrypt with appropriate parameters.",
    },
    {
        "id": "jwt-none",
        "pattern": re.compile(r'(?i)(?:algorithm|alg).{0,30}[\"\']none[\"\']|jwt\.(?:decode|verify)\s*\(.*verify\s*=\s*False'),
        "issue": "Potentially Unsafe JWT Verification",
        "category": "Authentication",
        "severity": "HIGH",
        "cwe": "CWE-347",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "attack_type": "Authentication bypass / token abuse",
        "risk": "Weak or disabled token verification can undermine the trust boundary around authenticated requests.",
        "remediation": "Explicitly allow only expected signing algorithms and verify signature, issuer, audience, expiration, and other required claims.",
    },
    {
        "id": "open-redirect",
        "pattern": re.compile(r'(?i)(?:redirect|location\.href|window\.location)\s*(?:\(|=).*?(?:request|req\.|query|params|next|url|return)'),
        "issue": "Possible Open Redirect",
        "category": "Input validation",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "attack_type": "Open redirect / phishing assistance",
        "risk": "A user-controlled redirect destination can send users from a trusted site to an untrusted destination.",
        "remediation": "Allow only local paths or an explicit allowlist of trusted destinations.",
    },
    {
        "id": "debug-enabled",
        "pattern": re.compile(r'(?i)\b(?:debug\s*=\s*True|app\.run\(.*debug\s*=\s*True)'),
        "issue": "Debug Mode Enabled",
        "category": "Security misconfiguration",
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "owasp": "A05:2021 - Security Misconfiguration",
        "attack_type": "Information disclosure / misconfiguration",
        "risk": "Debug features can disclose internal details and should not be enabled in production.",
        "remediation": "Disable debug mode in production and configure controlled error responses.",
    },
    {
        "id": "cors-wildcard",
        "pattern": re.compile(r'(?i)(?:Access-Control-Allow-Origin|cors).{0,100}[\"\']\*[\"\']'),
        "issue": "Permissive CORS Configuration",
        "category": "Security misconfiguration",
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "attack_type": "Cross-origin abuse",
        "risk": "An overly broad cross-origin policy can expose browser-accessible resources to untrusted origins depending on credentials and endpoint behavior.",
        "remediation": "Allow only trusted origins and use the narrowest CORS policy required by the application.",
    },
    {
        "id": "insecure-random",
        "pattern": re.compile(r'(?i)(?:random\.random|Math\.random|java\.util\.Random\s*\()'),
        "issue": "Non-Cryptographic Randomness Used in Security-Sensitive Code",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "owasp": "A02:2021 - Cryptographic Failures",
        "attack_type": "Token prediction / security control bypass",
        "risk": "Predictable randomness can weaken tokens, reset links, identifiers, or other security-sensitive values if used for those purposes.",
        "remediation": "Use a cryptographically secure random generator for secrets, tokens, reset links, and security-sensitive identifiers.",
    },
    {
        "id": "unsafe-jdbc-statement",
        "pattern": re.compile(r'(?i)Statement\s+\w+\s*=|\.executeQuery\s*\([^)]*\+|\.executeUpdate\s*\([^)]*\+'),
        "issue": "Potential SQL Injection in JDBC Statement",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "attack_type": "SQL injection",
        "risk": "String-built JDBC queries can become injectable when untrusted input is concatenated into SQL.",
        "remediation": "Use PreparedStatement with bound parameters instead of string concatenation.",
    },
    {
        "id": "php-command-exec",
        "pattern": re.compile(r'(?i)\b(?:system|shell_exec|passthru|exec|popen)\s*\('),
        "issue": "PHP Command Execution Sink",
        "category": "Injection",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "attack_type": "OS command injection",
        "risk": "Command execution functions can become dangerous when attacker-controlled data reaches them.",
        "remediation": "Avoid shell commands; if unavoidable, use strict allowlists and safe argument handling.",
    },
    {
        "id": "idor-pattern",
        "pattern": re.compile(r'(?i)(?:findById|findOne|find_by_id|objects\.get|Model\.findByPk)\s*\(\s*(?:req\.|request\.|params|query|input|user_id|id)'),
        "issue": "Potential Insecure Direct Object Reference (IDOR)",
        "category": "Authorization",
        "severity": "HIGH",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "attack_type": "Unauthorized object access / IDOR",
        "risk": "A user-controlled object identifier is used in a data lookup. Without an authorization check, one user may access another user's resource.",
        "remediation": "Enforce authorization against the authenticated user and the requested object before returning or modifying data.",
    },
]


def _mask_secret(text: str) -> str:
    if len(text) <= 10:
        return "*" * len(text)
    return text[:4] + "*" * max(4, len(text) - 8) + text[-4:]


def _evidence(line: str, secret: bool = False) -> str:
    clean = line.strip()[:700]
    if not secret:
        return clean
    return re.sub(
        r'([\"\'])([^\"\']{8,})(\1)',
        lambda m: m.group(1) + _mask_secret(m.group(2)) + m.group(1),
        clean,
    )


def _make_finding(rule: Dict[str, Any], file_name: str, lineno: int, line: str) -> Dict[str, Any]:
    return {
        "source": "SentinelAI static heuristics",
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
    }


def heuristic_scan(code: str, file_name: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append(_make_finding(rule, file_name, lineno, line))

    # Small cross-line checks catch common cases where input and dangerous sink
    # are separated by assignments.
    joined = "\n".join(lines)
    lower = joined.lower()

    if re.search(r'(?i)(request\.(?:args|form|json|query_params)|req\.(?:query|body|params))', joined) and re.search(r'(?i)(execute\s*\(|query\s*=|sql\s*=|cursor\.execute)', joined):
        if not any(f["cwe"] == "CWE-89" for f in findings):
            line_no = next((i for i, l in enumerate(lines, 1) if re.search(r'(?i)(execute\s*\(|cursor\.execute|query\s*=|sql\s*=)', l)), 1)
            rule = next(r for r in RULES if r["id"] == "sql-execute-variable")
            findings.append(_make_finding(rule, file_name, line_no, lines[line_no - 1]))

    if re.search(r'(?i)(request\.(?:args|form|json)|req\.(?:query|body|params))', joined) and re.search(r'(?i)(innerHTML|dangerouslySetInnerHTML|document\.write|render_template_string|mark_safe)', joined):
        if not any(f["cwe"] == "CWE-79" for f in findings):
            line_no = next((i for i, l in enumerate(lines, 1) if re.search(r'(?i)(innerHTML|dangerouslySetInnerHTML|document\.write|render_template_string|mark_safe)', l)), 1)
            rule = next(r for r in RULES if r["id"] == "xss-sink")
            findings.append(_make_finding(rule, file_name, line_no, lines[line_no - 1]))

    if re.search(r'(?i)(request\.(?:args|form|files)|req\.(?:query|body|params)).*(?:open\(|readFile|send_file)', joined, re.S):
        if not any(f["cwe"] == "CWE-22" for f in findings):
            line_no = next((i for i, l in enumerate(lines, 1) if re.search(r'(?i)(open\(|readFile|send_file)', l)), 1)
            rule = next(r for r in RULES if r["id"] == "path-traversal")
            findings.append(_make_finding(rule, file_name, line_no, lines[line_no - 1]))

    if re.search(r'(?i)(request\.(?:args|form|json)|req\.(?:query|body|params))', joined) and re.search(r'(?i)(os\.system|subprocess\.|child_process\.exec|shell=True)', joined):
        if not any(f["cwe"] == "CWE-78" for f in findings):
            line_no = next((i for i, l in enumerate(lines, 1) if re.search(r'(?i)(os\.system|subprocess\.|child_process\.exec|shell=True)', l)), 1)
            rule = next(r for r in RULES if r["id"] == "command-exec")
            findings.append(_make_finding(rule, file_name, line_no, lines[line_no - 1]))

    return findings


def semgrep_scan(code: str, file_name: str) -> List[Dict[str, Any]]:
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return []
    suffix = os.path.splitext(file_name)[1] or ".txt"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_path = f.name

        cmd = [semgrep_bin, "scan", "--config=p/owasp-top-ten", "--json", "--quiet", "--metrics=off", tmp_path]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
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

    seen: set[Tuple[Any, Any, Any]] = set()
    merged: List[Dict[str, Any]] = []
    for item in semgrep + heuristic:
        key = (item.get("line_start"), item.get("cwe"), item.get("issue"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "WARNING": 2}
    merged.sort(key=lambda x: (severity_order.get(str(x.get("severity")).upper(), 9), x.get("line_start") or 0))
    return merged
