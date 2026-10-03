# 🛡️ SentinelAI

SentinelAI is an AI-assisted defensive source-code security analyzer. It can review pasted source code, one uploaded source file, or a public/private GitHub repository **without executing the target application**.

## What SentinelAI checks

- SQL injection / unsafe database query construction
- XSS and unsafe HTML sinks
- OS command injection sinks
- Dynamic code execution (`eval`, `exec`, etc.)
- Hardcoded secrets and credentials
- Path traversal indicators
- SSRF indicators
- Unsafe deserialization
- Disabled TLS certificate verification
- Weak cryptography and password hashing indicators
- JWT verification weaknesses
- Open redirects
- Debug mode and permissive CORS
- Non-cryptographic randomness in security-sensitive code
- Potential IDOR / authorization weaknesses
- Semgrep OWASP Top 10 findings when Semgrep is available
- AI review of the source itself, including cases where local static rules find nothing

## Inputs

### 1. Paste Code
Paste source code and select its language.

### 2. Upload One Code File
Upload a single source file. Project ZIP uploads are intentionally not used.

### 3. GitHub Repository
Enter a repository URL such as:

`https://github.com/owner/repository`

Public repositories work without a GitHub token. Private repositories require `GITHUB_TOKEN` in Streamlit Secrets.

SentinelAI downloads repository source to a temporary directory, scans supported source files, and does not execute the repository.

## Security report

For each potential issue SentinelAI reports:

- Severity
- CWE / OWASP mapping
- File and line
- Evidence
- Why the code is risky
- Potential attack type
- Potential impact
- Recommended remediation

The report deliberately describes **potential attack impact**, not proof that a real target is exploitable. AI explanations are also instructed not to provide operational exploit payloads or step-by-step attacks.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Streamlit Secrets

Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and add the keys you want to use:

```toml
GROQ_API_KEY = "..."
GEMINI_API_KEY = "..."
GITHUB_TOKEN = "..."
```

Groq/Gemini are optional. GitHub token is only required for private repositories.
