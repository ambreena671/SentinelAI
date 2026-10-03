import subprocess
import json
import os
import shutil
from typing import List, Dict, Any

def run_semgrep_sast(repo_path: str, timeout: int = 45, log_callback=None) -> List[Dict[str, Any]]:
    """
    Runs Semgrep CLI with OWASP ruleset against the cloned repository directory.
    Returns structured findings list safely without throwing unhandled exceptions.
    """
    def audit_log(msg: str):
        if log_callback:
            log_callback(msg)

    audit_log(f"[SAST Agent] Verifying repository path: {repo_path}")
    if not os.path.exists(repo_path):
        audit_log("[SAST Error] Directory does not exist.")
        return []

    # Check if semgrep executable exists in PATH
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        audit_log("[SAST Warning] 'semgrep' binary not found in PATH. Skipping SAST scan.")
        return []

    cmd = [
        semgrep_bin,
        "scan",
        "--config=p/owasp-top-ten",
        "--json",
        "--quiet",
        repo_path
    ]

    audit_log("[SAST Agent] Executing Semgrep OWASP scan ruleset...")
    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        
        if process.returncode not in [0, 1]:  # 0 = clean, 1 = findings found
            audit_log(f"[SAST Warning] Semgrep process returned code {process.returncode}: {process.stderr[:200]}")
            return []

        data = json.loads(process.stdout)
        results = []
        for match in data.get("results", []):
            extra = match.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe = metadata.get("cwe", ["CWE-Unknown"])
            cwe_str = cwe[0] if isinstance(cwe, list) and cwe else "CWE-Unknown"

            results.append({
                "source": "SAST (Semgrep)",
                "check_id": match.get("check_id"),
                "file_path": match.get("path"),
                "line_start": match.get("start", {}).get("line"),
                "line_end": match.get("end", {}).get("line"),
                "severity": extra.get("severity", "WARNING").upper(),
                "message": extra.get("message", "No description provided."),
                "cwe": cwe_str,
                "lines": extra.get("lines", "")
            })

        audit_log(f"[SAST Agent] Scan finished. Found {len(results)} potential code issues.")
        return results

    except subprocess.TimeoutExpired:
        audit_log(f"[SAST Warning] Semgrep scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        audit_log(f"[SAST Error] Failed to complete Semgrep analysis: {str(e)}")
        return []