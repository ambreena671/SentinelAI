# 🛡️ SentinelAI

AI-powered source-code and GitHub repository security analyzer for hackathons and developer security review.

## What SentinelAI does

SentinelAI analyzes source code **without executing the submitted application**.

A user can:

1. Paste source code,
2. Upload one source-code file, or
3. Enter a GitHub repository URL.

For GitHub repositories, SentinelAI downloads the repository source into a temporary workspace, scans supported source files, and removes the temporary workspace after analysis. The project itself is never executed.

## Analysis pipeline

```text
Paste Code / Source File / GitHub Repository
                    ↓
             Source Collection
                    ↓
        Static Security Analysis
             ┌──────┴──────┐
             │             │
          Heuristics     Semgrep
             │             │
             └──────┬──────┘
                    ↓
               OWASP / CWE RAG
                    ↓
                 AI Analyst
                    ↓
       Security Findings + Impact
                    ↓
              Remediation Report
```

## Findings covered

- SQL injection
- Cross-site scripting (XSS)
- OS command injection
- Dynamic code execution
- Path traversal
- Server-side request forgery (SSRF)
- Hardcoded credentials and secrets
- Weak cryptography
- Debug mode / security misconfiguration
- Permissive CORS
- Authentication and session security signals
- Additional Semgrep OWASP findings when Semgrep is available

## GitHub repository scanning

Use a URL such as:

```text
https://github.com/owner/repository
```

Public repositories work without a GitHub token.

For private repositories, add `GITHUB_TOKEN` to Streamlit Secrets. The token should have only the repository access required for the repositories you intend to scan.

SentinelAI does not run repository code, install the repository's dependencies, or start its server.

## Run locally

```bash
python -m venv .venv
```

Windows:

```bash
.venv\\Scripts\\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
streamlit run app.py
```

## Optional secrets

Create `.streamlit/secrets.toml`:

```toml
GROQ_API_KEY = "your-key"
GEMINI_API_KEY = "your-key"
GITHUB_TOKEN = "your-github-token"
```

The static scanner still works without AI keys. Public GitHub scanning works without a GitHub token.

## Interpretation

A static finding is a **potential vulnerability**, not proof that a real application is exploitable. SentinelAI distinguishes scanner evidence from AI reasoning and uses non-operational descriptions of possible attack types.

## Safety limits

- Repository archives have download and extraction limits.
- Unsafe archive paths and symbolic links are rejected.
- Generated/vendor directories are skipped.
- Submitted repositories are treated as untrusted data.
- SentinelAI does not execute submitted project code.
- AI output is instructed not to provide operational attack payloads or step-by-step exploitation procedures.
