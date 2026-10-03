import json
import os
import shutil
import streamlit as st

from agents.llm_fallback import ResilientLLMClient
from tools.code_scanner import scan_source_code
from tools.rag_tool import LightweightRAGTool
from tools.repository_loader import (
    clone_github_repository,
    iter_source_files,
    read_source_file,
)

st.set_page_config(
    page_title="SentinelAI - AI Code Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SentinelAI")
st.caption("AI-powered source-code and GitHub repository security analysis")
st.markdown(
    "Analyze source code without running the application. Paste code, upload one code file, "
    "or scan a GitHub repository. SentinelAI identifies potential security weaknesses, maps "
    "them to OWASP/CWE, and explains what kinds of attacks the weakness could enable."
)

with st.sidebar:
    st.header("⚙️ Scanner")
    demo_mode = st.toggle("Demo mode", help="Use bundled findings to demonstrate the report UI.")
    st.divider()
    st.markdown("### 🤖 AI status")
    groq_ok = bool(os.getenv("GROQ_API_KEY"))
    gemini_ok = bool(os.getenv("GEMINI_API_KEY"))
    github_ok = bool(os.getenv("GITHUB_TOKEN"))
    try:
        groq_ok = groq_ok or "GROQ_API_KEY" in st.secrets
        gemini_ok = gemini_ok or "GEMINI_API_KEY" in st.secrets
        github_ok = github_ok or "GITHUB_TOKEN" in st.secrets
    except Exception:
        pass
    st.write(f"Groq: {'✅ configured' if groq_ok else '⚪ optional'}")
    st.write(f"Gemini: {'✅ configured' if gemini_ok else '⚪ optional'}")
    st.write(f"GitHub token: {'✅ configured' if github_ok else '⚪ public repos work'}")
    st.caption("Private GitHub repositories require a token with access. Public repositories do not.")

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if demo_mode:
    st.info("Demo mode is enabled. No external source is scanned.")
    source_mode = "Demo"
else:
    source_mode = st.radio(
        "🧩 Choose analysis source",
        ["Paste Code", "Upload One Code File", "GitHub Repository"],
        horizontal=True,
    )

code_text = ""
file_name = "pasted_code.py"
repo_metadata = None
repo_temp_dir = None

if source_mode == "Paste Code":
    language = st.selectbox(
        "Language",
        ["Python", "JavaScript", "TypeScript", "Java", "PHP", "C#", "Go", "Ruby", "SQL", "HTML"],
    )
    extension_map = {
        "Python": ".py", "JavaScript": ".js", "TypeScript": ".ts", "Java": ".java",
        "PHP": ".php", "C#": ".cs", "Go": ".go", "Ruby": ".rb", "SQL": ".sql", "HTML": ".html",
    }
    file_name = "pasted_code" + extension_map[language]
    code_text = st.text_area(
        "Paste your source code",
        height=420,
        placeholder="Paste the code you want SentinelAI to review...",
    )

elif source_mode == "Upload One Code File":
    uploaded = st.file_uploader(
        "Upload one source-code file",
        type=[
            "py", "js", "jsx", "ts", "tsx", "java", "php", "cs", "go", "rb", "rs",
            "kt", "kts", "swift", "sql", "html", "htm", "css", "scss", "vue", "c",
            "cpp", "h", "hpp", "sh", "bash", "dart", "lua",
        ],
        help="Upload a single source file. Project ZIP uploads are not used.",
    )
    if uploaded is not None:
        file_name = uploaded.name
        code_text = uploaded.getvalue().decode("utf-8", errors="replace")
        st.code(code_text[:12000], language="text")
        if len(code_text) > 12000:
            st.caption("Preview truncated. The complete file is analyzed.")

elif source_mode == "GitHub Repository":
    github_url = st.text_input(
        "GitHub repository URL",
        placeholder="https://github.com/owner/repository",
        help="Public repositories work without a token. Private repositories require GITHUB_TOKEN.",
    )
    st.caption("SentinelAI downloads the repository source into a temporary workspace and scans source files. It does not execute the project.")
    load_repo = st.button("📥 Load GitHub Repository", type="secondary", use_container_width=True)
    if load_repo:
        if not github_url.strip():
            st.error("Enter a GitHub repository URL first.")
        else:
            try:
                token = os.getenv("GITHUB_TOKEN")
                try:
                    token = token or st.secrets.get("GITHUB_TOKEN")
                except Exception:
                    pass
                with st.spinner("Loading GitHub repository..."):
                    repo_temp_dir, repo_metadata = clone_github_repository(github_url, token=token)
                st.session_state.repo_temp_dir = repo_temp_dir
                st.session_state.repo_metadata = repo_metadata
                st.success(f"Loaded {repo_metadata['repository']} ({repo_metadata['branch']})")
            except Exception as exc:
                st.error(f"Could not load repository: {exc}")

    repo_temp_dir = st.session_state.get("repo_temp_dir")
    repo_metadata = st.session_state.get("repo_metadata")
    if repo_temp_dir and repo_metadata:
        st.info(f"Repository ready: {repo_metadata['repository']} · branch `{repo_metadata['branch']}`")

st.divider()

scan_clicked = st.button(
    "🔍 Analyze Security",
    type="primary",
    use_container_width=True,
    disabled=(
        not demo_mode
        and ((source_mode != "GitHub Repository" and not code_text.strip())
             or (source_mode == "GitHub Repository" and not repo_temp_dir))
    ),
)


def build_prompt(findings, guidance, source_name, scan_type, source_code=""):
    code_section = source_code[:30000] if source_code else "(Source excerpt unavailable; reason from scanner findings only.)"
    return f"""
You are SentinelAI, a senior defensive application-security analyst.

Analyze static-analysis findings from {scan_type}.

For each important finding explain:
1. Vulnerability name
2. Severity
3. CWE / OWASP mapping if available
4. File and line
5. Scanner evidence
6. What security weakness exists
7. What kind of attack or abuse could be possible
8. Potential confidentiality, integrity, or availability impact
9. A short, non-operational attack path in plain English
10. How the developer should fix it
11. A small safer-code example when reasonable

Important:
- A static finding is not proof of exploitability. Use "could enable" or "may allow" when appropriate.
- Do not provide attack payloads, commands, exploit chains, or step-by-step procedures against real systems.
- Never reveal a complete credential or token. Redact secrets.
- Distinguish scanner evidence from your reasoning.
- If context is insufficient, explicitly say that manual review is required.

Source: {source_name}

Findings:
{json.dumps(findings, indent=2)}

OWASP/CWE guidance:
{json.dumps(guidance, indent=2)}

Source code excerpt for independent review:
```text
{code_section}
```

Even when the static finding list is empty, perform an independent security review of the source excerpt. Look for missing validation, authorization, authentication, CSRF protection, unsafe output handling, secrets, insecure cryptography, unsafe file access, SSRF, injection, insecure deserialization, and security misconfiguration when the code context supports such a conclusion. Do not invent a vulnerability when the evidence is insufficient.
"""


def severity_count(findings, level):
    return sum(1 for item in findings if str(item.get("severity", "")).upper() == level)


def analyze_files(file_items, scan_type, source_name):
    all_findings = []
    source_for_ai = "\n\n".join(
        f"### {name}\n{text[:12000]}" for name, text in file_items[:5]
    )
    progress = st.progress(0, text="Starting source analysis...")
    total = len(file_items)
    for index, (relative_name, text) in enumerate(file_items, start=1):
        findings = scan_source_code(text, file_name=relative_name)
        all_findings.extend(findings)
        progress.progress(index / max(total, 1), text=f"Scanning {relative_name} ({index}/{total})")
    progress.empty()

    rag = LightweightRAGTool()
    guidance = rag.retrieve_guidance(json.dumps(all_findings), top_k=8)
    llm = ResilientLLMClient()
    summary = llm.generate(build_prompt(all_findings, guidance, source_name, scan_type, source_for_ai))

    return {
        "product": "SentinelAI",
        "scan_type": scan_type,
        "source": source_name,
        "files_scanned": total,
        "finding_count": len(all_findings),
        "findings": all_findings,
        "rag_guidance": guidance,
        "executive_summary": summary,
    }


if scan_clicked:
    try:
        if demo_mode:
            with open("sample_data/demo_findings.json", "r", encoding="utf-8") as f:
                findings_data = json.load(f)
        elif source_mode == "GitHub Repository":
            files = iter_source_files(repo_temp_dir)
            if not files:
                raise ValueError("No supported source-code files were found in this repository.")
            file_items = [read_source_file(path, repo_temp_dir) for path in files]
            findings_data = analyze_files(
                file_items,
                "GitHub Repository Security Audit",
                repo_metadata["repository"],
            )
            findings_data["repository"] = repo_metadata
        else:
            findings_data = analyze_files(
                [(file_name, code_text)],
                "Single Source File Security Audit",
                file_name,
            )

        st.session_state.scan_result = findings_data
    except Exception as exc:
        st.session_state.scan_result = None
        st.error(f"Analysis failed: {exc}")
    finally:
        # Repository source is only needed during the current analysis session.
        # It is intentionally never executed.
        if source_mode == "GitHub Repository" and st.session_state.get("repo_temp_dir"):
            shutil.rmtree(st.session_state.repo_temp_dir, ignore_errors=True)
            st.session_state.repo_temp_dir = None

findings_data = st.session_state.scan_result

if findings_data:
    findings = findings_data.get("findings", [])
    st.divider()
    st.subheader("📊 Security Overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🔴 Critical", severity_count(findings, "CRITICAL"))
    c2.metric("🟠 High", severity_count(findings, "HIGH"))
    c3.metric("🟡 Medium", severity_count(findings, "MEDIUM"))
    c4.metric("🔵 Low", severity_count(findings, "LOW"))
    st.caption(f"Scanned {findings_data.get('files_scanned', 1)} source file(s).")

    st.subheader("🤖 AI Security Assessment")
    st.markdown(findings_data.get("executive_summary", "AI explanation unavailable."))

    st.subheader("🔎 Security Findings")
    if not findings:
        st.info("No findings were triggered by the local static rules. This does not prove the code is vulnerability-free; the AI assessment above also reviews the source excerpt for additional security weaknesses.")

    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "INFO")).upper()
        title = finding.get("issue") or "Security finding"
        with st.expander(f"{index}. [{severity}] {title}", expanded=severity in {"CRITICAL", "HIGH"}):
            left, right = st.columns(2)
            with left:
                st.write(f"**Category:** {finding.get('category', 'N/A')}")
                st.write(f"**CWE:** {finding.get('cwe', 'N/A')}")
                st.write(f"**OWASP:** {finding.get('owasp', 'N/A')}")
                st.write(f"**File:** `{finding.get('file_path', 'N/A')}`")
                st.write(f"**Line:** {finding.get('line_start', 'N/A')}")
            with right:
                st.write(f"**Confidence:** {finding.get('confidence', 'Potential')}")
                st.write(f"**Attack type:** {finding.get('attack_type', 'Security abuse')}")
                st.write(f"**Potential impact:** {finding.get('risk', 'See assessment.')}")
            if finding.get("evidence"):
                st.markdown("**Evidence**")
                st.code(str(finding["evidence"]), language="text")
            if finding.get("remediation"):
                st.markdown("**Recommended fix**")
                st.info(finding["remediation"])

    st.subheader("📚 Matched OWASP/CWE Guidance")
    for item in findings_data.get("rag_guidance", []):
        st.markdown(
            f"**{item.get('id', '')} — {item.get('name', 'Guidance')}**  \n"
            f"{item.get('remediation', '')}"
        )

    report_md = (
        "# 🛡️ SentinelAI Security Report\n\n"
        f"**Scan type:** {findings_data.get('scan_type', 'Security Audit')}\n\n"
        f"**Source:** `{findings_data.get('source', 'unknown')}`\n\n"
        "## AI Assessment\n\n"
        f"{findings_data.get('executive_summary', 'Not available')}\n\n"
        "## Technical Findings\n\n"
        "```json\n"
        f"{json.dumps(findings_data, indent=2)}\n"
        "```\n"
    )
    st.download_button(
        "📥 Download SentinelAI Security Report",
        report_md,
        file_name="sentinelai_security_report.md",
        mime="text/markdown",
        use_container_width=True,
    )
