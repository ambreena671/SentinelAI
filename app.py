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


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.header("⚙️ Scanner")

    demo_mode = st.toggle(
        "Demo mode",
        help="Use bundled findings to demonstrate the report UI.",
    )

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

    st.write(
        f"Groq: {'✅ configured' if groq_ok else '⚪ optional'}"
    )

    st.write(
        f"Gemini: {'✅ configured' if gemini_ok else '⚪ optional'}"
    )

    st.write(
        f"GitHub token: {'✅ configured' if github_ok else '⚪ public repos work'}"
    )

    st.caption(
        "Private GitHub repositories require a token with access. "
        "Public repositories do not."
    )


# ============================================================
# SESSION STATE
# ============================================================

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "repo_temp_dir" not in st.session_state:
    st.session_state.repo_temp_dir = None

if "repo_metadata" not in st.session_state:
    st.session_state.repo_metadata = None


# ============================================================
# SOURCE SELECTION
# ============================================================

if demo_mode:

    st.info(
        "Demo mode is enabled. No external source is scanned."
    )

    source_mode = "Demo"

else:

    source_mode = st.radio(
        "🧩 Choose analysis source",
        [
            "Paste Code",
            "Upload One Code File",
            "GitHub Repository",
        ],
        horizontal=True,
    )


code_text = ""
file_name = "pasted_code.py"

repo_metadata = None
repo_temp_dir = None


# ============================================================
# PASTE CODE
# ============================================================

if source_mode == "Paste Code":

    language = st.selectbox(
        "Language",
        [
            "Python",
            "JavaScript",
            "TypeScript",
            "Java",
            "PHP",
            "C#",
            "Go",
            "Ruby",
            "SQL",
            "HTML",
        ],
    )

    extension_map = {
        "Python": ".py",
        "JavaScript": ".js",
        "TypeScript": ".ts",
        "Java": ".java",
        "PHP": ".php",
        "C#": ".cs",
        "Go": ".go",
        "Ruby": ".rb",
        "SQL": ".sql",
        "HTML": ".html",
    }

    file_name = "pasted_code" + extension_map[language]

    code_text = st.text_area(
        "Paste your source code",
        height=420,
        placeholder="Paste the code you want SentinelAI to review...",
    )


# ============================================================
# UPLOAD ONE FILE
# ============================================================

elif source_mode == "Upload One Code File":

    uploaded = st.file_uploader(
        "Upload one source-code file",
        type=[
            "py",
            "js",
            "jsx",
            "ts",
            "tsx",
            "java",
            "php",
            "cs",
            "go",
            "rb",
            "rs",
            "kt",
            "kts",
            "swift",
            "sql",
            "html",
            "htm",
            "css",
            "scss",
            "vue",
            "c",
            "cpp",
            "h",
            "hpp",
            "sh",
            "bash",
            "dart",
            "lua",
        ],
        help="Upload a single source file. Project ZIP uploads are not used.",
    )

    if uploaded is not None:

        file_name = uploaded.name

        code_text = uploaded.getvalue().decode(
            "utf-8",
            errors="replace",
        )

        st.code(
            code_text[:12000],
            language="text",
        )

        if len(code_text) > 12000:
            st.caption(
                "Preview truncated. The complete file is analyzed."
            )


# ============================================================
# GITHUB REPOSITORY
# ============================================================

elif source_mode == "GitHub Repository":

    github_url = st.text_input(
        "GitHub repository URL",
        placeholder="https://github.com/owner/repository",
        help=(
            "Public repositories work without a token. "
            "Private repositories require GITHUB_TOKEN."
        ),
    )

    st.caption(
        "SentinelAI downloads the repository source into a temporary "
        "workspace and scans source files. It does not execute the project."
    )

    load_repo = st.button(
        "📥 Load GitHub Repository",
        type="secondary",
        use_container_width=True,
    )

    if load_repo:

        if not github_url.strip():

            st.error(
                "Enter a GitHub repository URL first."
            )

        else:

            try:

                token = os.getenv("GITHUB_TOKEN")

                try:
                    token = token or st.secrets.get(
                        "GITHUB_TOKEN"
                    )
                except Exception:
                    pass

                with st.spinner(
                    "Loading GitHub repository..."
                ):

                    repo_temp_dir, repo_metadata = (
                        clone_github_repository(
                            github_url,
                            token=token,
                        )
                    )

                st.session_state.repo_temp_dir = repo_temp_dir
                st.session_state.repo_metadata = repo_metadata

                st.success(
                    f"Loaded {repo_metadata['repository']} "
                    f"({repo_metadata['branch']})"
                )

            except Exception as exc:

                st.error(
                    f"Could not load repository: {exc}"
                )

    repo_temp_dir = st.session_state.get(
        "repo_temp_dir"
    )

    repo_metadata = st.session_state.get(
        "repo_metadata"
    )

    if repo_temp_dir and repo_metadata:

        st.info(
            f"Repository ready: "
            f"{repo_metadata['repository']} · "
            f"branch `{repo_metadata['branch']}`"
        )


# ============================================================
# ANALYZE BUTTON
# ============================================================

st.divider()

scan_clicked = st.button(
    "🔍 Analyze Security",
    type="primary",
    use_container_width=True,
    disabled=(
        not demo_mode
        and (
            (
                source_mode != "GitHub Repository"
                and not code_text.strip()
            )
            or (
                source_mode == "GitHub Repository"
                and not repo_temp_dir
            )
        )
    ),
)


# ============================================================
# AI PROMPT
# ============================================================

def build_prompt(findings, guidance, source_name, scan_type, source_code=""):
    code_section = (
        source_code[:30000]
        if source_code
        else "(Source excerpt unavailable; reason from scanner findings only.)"
    )

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
