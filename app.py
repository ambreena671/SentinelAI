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


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SentinelAI - AI Code Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SentinelAI")
st.caption("AI-powered source-code and GitHub repository security analysis")

st.markdown(
    "Analyze source code without running the application. "
    "Paste code, upload one code file, or scan a GitHub repository. "
    "SentinelAI identifies potential security weaknesses, maps them "
    "to OWASP/CWE, and uses AI to review the actual source code."
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
        f"GitHub token: "
        f"{'✅ configured' if github_ok else '⚪ public repos work'}"
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

repo_metadata = st.session_state.get("repo_metadata")
repo_temp_dir = st.session_state.get("repo_temp_dir")


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
                    token = token or st.secrets.get("GITHUB_TOKEN")
                except Exception:
                    pass

                with st.spinner(
                    "Loading GitHub repository..."
                ):

                    loaded_dir, loaded_metadata = (
                        clone_github_repository(
                            github_url,
                            token=token,
                        )
                    )

                st.session_state.repo_temp_dir = loaded_dir
                st.session_state.repo_metadata = loaded_metadata

                repo_temp_dir = loaded_dir
                repo_metadata = loaded_metadata

                st.success(
                    f"Loaded {loaded_metadata['repository']} "
                    f"({loaded_metadata['branch']})"
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
)


# ============================================================
# AI PROMPT
# ============================================================

def build_prompt(
    findings,
    guidance,
    source_name,
    scan_type,
    source_code="",
):
    code_section = (
        source_code[:30000]
        if source_code
        else "(Source excerpt unavailable.)"
    )

    findings_text = json.dumps(
        findings,
        indent=2,
    )

    guidance_text = json.dumps(
        guidance,
        indent=2,
    )

    prompt_parts = [
        "You are SentinelAI, a senior defensive "
        "application-security analyst.",

        "",

        f"Analyze the following {scan_type}.",

        "",

        "Your job is to perform a defensive security review "
        "of the supplied source code.",

        "",

        "For each important security issue explain:",

        "1. Vulnerability name",
        "2. Severity",
        "3. CWE / OWASP mapping if supported",
        "4. File and line",
        "5. Evidence from the source code",
        "6. Why the code is potentially risky",
        "7. General attack or abuse type",
        "8. Potential security impact",
        "9. Short non-operational attack path",
        "10. Recommended remediation",
        "11. Safer code example when useful",

        "",

        "Important rules:",

        "- Do not invent vulnerabilities.",
        "- Static findings are potential issues, not automatic proof of exploitability.",
        "- Clearly separate scanner evidence from your reasoning.",
        "- Do not provide exploit payloads.",
        "- Do not provide attack commands.",
        "- Do not provide step-by-step exploitation instructions.",
        "- Never expose complete credentials or API keys.",
        "- Redact secrets if they appear in source.",
        "- If there is insufficient evidence, say that manual review is required.",

        "",

        f"Source name: {source_name}",

        "",

        "STATIC SCANNER FINDINGS:",
        findings_text,

        "",

        "OWASP/CWE RAG GUIDANCE:",
        guidance_text,

        "",

        "SOURCE CODE FOR INDEPENDENT AI REVIEW:",
        "```text",
        code_section,
        "```",

        "",

        "Even if the static scanner found zero issues, "
        "independently review the source code for security weaknesses.",

        "Consider when supported by the actual code:",
        "- input validation",
        "- authentication",
        "- authorization",
        "- CSRF protection",
        "- unsafe output handling",
        "- secrets and credentials",
        "- cryptography",
        "- file access",
        "- SSRF",
        "- SQL injection",
        "- command injection",
        "- XSS",
        "- insecure deserialization",
        "- path traversal",
        "- security misconfiguration",

        "",

        "Do not claim a vulnerability unless the supplied "
        "source provides reasonable evidence.",
    ]

    return "\n".join(prompt_parts)


# ============================================================
# SEVERITY COUNTER
# ============================================================

def severity_count(findings, level):
    return sum(
        1
        for item in findings
        if str(
            item.get("severity", "")
        ).upper() == level
    )


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def analyze_files(
    file_items,
    scan_type,
    source_name,
):
    if not file_items:
        raise ValueError(
            "No source files were provided for analysis."
        )

    # --------------------------------------------------------
    # STEP 1 - STATIC SCANNING
    # --------------------------------------------------------

    st.info(
        "🔎 Step 1/4 — Running static security scanner..."
    )

    all_findings = []

    source_for_ai = "\n\n".join(
        f"### {name}\n{text[:10000]}"
        for name, text in file_items[:5]
    )

    total = len(file_items)

    progress = st.progress(
        0,
        text="Starting source analysis...",
    )

    for index, (relative_name, text) in enumerate(
        file_items,
        start=1,
    ):

        st.write(
            f"Scanning `{relative_name}`..."
        )

        try:

            findings = scan_source_code(
                text,
                file_name=relative_name,
            )

            if findings:
                all_findings.extend(
                    findings
                )

        except Exception as exc:

            st.warning(
                f"Scanner error in `{relative_name}`: "
                f"{type(exc).__name__}: {exc}"
            )

        progress.progress(
            index / total,
            text=(
                f"Scanned {relative_name} "
                f"({index}/{total})"
            ),
        )

    progress.empty()

    st.success(
        f"✅ Static scan complete — "
        f"{len(all_findings)} potential finding(s)."
    )

    # --------------------------------------------------------
    # STEP 2 - RAG
    # --------------------------------------------------------

    st.info(
        "📚 Step 2/4 — Matching findings with OWASP/CWE knowledge..."
    )

    rag = LightweightRAGTool()

    try:

        guidance = rag.retrieve_guidance(
            json.dumps(all_findings),
            top_k=8,
        )

    except Exception as exc:

        st.warning(
            f"RAG lookup failed: "
            f"{type(exc).__name__}: {exc}"
        )

        guidance = []

    st.success(
        f"✅ RAG matching complete — "
        f"{len(guidance)} guidance item(s)."
    )

    # --------------------------------------------------------
    # STEP 3 - AI
    # --------------------------------------------------------

    st.info(
        "🤖 Step 3/4 — AI is reviewing the actual source code..."
    )

    prompt = build_prompt(
        all_findings,
        guidance,
        source_name,
        scan_type,
        source_for_ai,
    )

    st.caption(
        f"AI prompt prepared: {len(prompt):,} characters"
    )

    llm = ResilientLLMClient()

    try:

        summary = llm.generate(
            prompt,
            timeout=30,
        )

        if not summary:
            summary = (
                "AI returned an empty response."
            )

    except Exception as exc:

        summary = (
            "### AI analysis failed\n\n"
            f"**Error:** `{type(exc).__name__}: {exc}`\n\n"
            "The static security findings are still available below."
        )

        st.error(
            f"AI request failed: {type(exc).__name__}: {exc}"
        )

    st.success(
        "✅ AI analysis completed."
    )

    # --------------------------------------------------------
    # STEP 4 - REPORT
    # --------------------------------------------------------

    st.info(
        "📊 Step 4/4 — Preparing security report..."
    )

    result = {
        "product": "SentinelAI",
        "scan_type": scan_type,
        "source": source_name,
        "files_scanned": total,
        "finding_count": len(all_findings),
        "findings": all_findings,
        "rag_guidance": guidance,
        "executive_summary": summary,
    }

    st.success(
        "🎉 SentinelAI analysis complete."
    )

    return result


# ============================================================
# RUN ANALYSIS
# ============================================================

if scan_clicked:

    st.divider()

    st.subheader(
        "🚀 SentinelAI Analysis Started"
    )

    try:

        st.write(
            f"**Source mode:** {source_mode}"
        )

        # ----------------------------------------------------
        # DEMO
        # ----------------------------------------------------

        if demo_mode:

            st.info(
                "Demo mode is active."
            )

            with open(
                "sample_data/demo_findings.json",
                "r",
                encoding="utf-8",
            ) as f:

                findings_data = json.load(f)

            st.success(
                "✅ Demo findings loaded."
            )

        # ----------------------------------------------------
        # GITHUB
        # ----------------------------------------------------

        elif source_mode == "GitHub Repository":

            st.info(
                "📦 Preparing GitHub repository..."
            )

            if not repo_temp_dir:

                raise ValueError(
                    "No repository is loaded. "
                    "Click 'Load GitHub Repository' first."
                )

            files = list(
                iter_source_files(
                    repo_temp_dir
                )
            )

            st.write(
                f"Found **{len(files)}** "
                f"supported source file(s)."
            )

            if not files:

                raise ValueError(
                    "No supported source-code files "
                    "were found in this repository."
                )

            file_items = []

            for path in files:

                try:

                    item = read_source_file(
                        path,
                        repo_temp_dir,
                    )

                    file_items.append(item)

                except Exception as exc:

                    st.warning(
                        f"Could not read `{path}`: "
                        f"{type(exc).__name__}: {exc}"
                    )

            if not file_items:

                raise ValueError(
                    "The repository was found, but "
                    "no source files could be read."
                )

            findings_data = analyze_files(
                file_items,
                "GitHub Repository Security Audit",
                repo_metadata["repository"],
            )

            findings_data["repository"] = (
                repo_metadata
            )

        # ----------------------------------------------------
        # SINGLE FILE / PASTE
        # ----------------------------------------------------

        else:

            if not code_text.strip():

                raise ValueError(
                    "No source code was provided."
                )

            st.write(
                f"Analyzing `{file_name}` "
                f"({len(code_text):,} characters)..."
            )

            findings_data = analyze_files(
                [(file_name, code_text)],
                "Single Source File Security Audit",
                file_name,
            )

        st.session_state.scan_result = (
            findings_data
        )

        st.success(
            "🎉 SentinelAI finished the security analysis."
        )

    except Exception as exc:

        st.session_state.scan_result = None

        st.error(
            f"❌ Analysis failed: "
            f"{type(exc).__name__}: {exc}"
        )

        st.exception(exc)


# ============================================================
# RESULTS
# ============================================================

findings_data = (
    st.session_state.get("scan_result")
)


if findings_data:

    findings = findings_data.get(
        "findings",
        [],
    )

    st.divider()

    # --------------------------------------------------------
    # SECURITY OVERVIEW
    # --------------------------------------------------------

    st.subheader(
        "📊 Security Overview"
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "🔴 Critical",
        severity_count(
            findings,
            "CRITICAL",
        ),
    )

    c2.metric(
        "🟠 High",
        severity_count(
            findings,
            "HIGH",
        ),
    )

    c3.metric(
        "🟡 Medium",
        severity_count(
            findings,
            "MEDIUM",
        ),
    )

    c4.metric(
        "🔵 Low",
        severity_count(
            findings,
            "LOW",
        ),
    )

    st.caption(
        f"Scanned "
        f"{findings_data.get('files_scanned', 1)} "
        f"source file(s)."
    )

    # --------------------------------------------------------
    # AI ASSESSMENT
    # --------------------------------------------------------

    st.subheader(
        "🤖 AI Security Assessment"
    )

    st.markdown(
        findings_data.get(
            "executive_summary",
            "AI explanation unavailable.",
        )
    )

    # --------------------------------------------------------
    # STATIC FINDINGS
    # --------------------------------------------------------

    st.subheader(
        "🔎 Security Findings"
    )

    if not findings:

        st.info(
            "No findings were triggered by the local "
            "static rules. This does not prove the code "
            "is vulnerability-free. The AI assessment "
            "also reviewed the source excerpt."
        )

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        title = (
            finding.get("issue")
            or finding.get("title")
            or "Security finding"
        )

        with st.expander(
            f"{index}. [{severity}] {title}",
            expanded=severity in {
                "CRITICAL",
                "HIGH",
            },
        ):

            left, right = st.columns(2)

            with left:

                st.write(
                    f"**Category:** "
                    f"{finding.get('category', 'N/A')}"
                )

                st.write(
                    f"**CWE:** "
                    f"{finding.get('cwe', 'N/A')}"
                )

                st.write(
                    f"**OWASP:** "
                    f"{finding.get('owasp', 'N/A')}"
                )

                st.write(
                    f"**File:** "
                    f"`{finding.get('file_path', 'N/A')}`"
                )

                st.write(
                    f"**Line:** "
                    f"{finding.get('line_start', 'N/A')}"
                )

            with right:

                st.write(
                    f"**Confidence:** "
                    f"{finding.get('confidence', 'Potential')}"
                )

                st.write(
                    f"**Attack type:** "
                    f"{finding.get('attack_type', 'Security abuse')}"
                )

                st.write(
                    f"**Potential impact:** "
                    f"{finding.get('risk', 'See assessment.')}"
                )

            if finding.get("evidence"):

                st.markdown(
                    "**Evidence**"
                )

                st.code(
                    str(
                        finding["evidence"]
                    ),
                    language="text",
                )

            if finding.get("remediation"):

                st.markdown(
                    "**Recommended fix**"
                )

                st.info(
                    finding["remediation"]
                )

    # --------------------------------------------------------
    # RAG GUIDANCE
    # --------------------------------------------------------

    st.subheader(
        "📚 Matched OWASP/CWE Guidance"
    )

    guidance_items = findings_data.get(
        "rag_guidance",
        [],
    )

    if not guidance_items:

        st.caption(
            "No matching OWASP/CWE guidance was returned."
        )

    for item in guidance_items:

        st.markdown(
            f"**{item.get('id', '')} — "
            f"{item.get('name', 'Guidance')}**"
        )

        if item.get("description"):

            st.write(
                item["description"]
            )

        if item.get("remediation"):

            st.info(
                item["remediation"]
            )

    # --------------------------------------------------------
    # DOWNLOAD REPORT
    # --------------------------------------------------------

    report_md = (
        "# 🛡️ SentinelAI Security Report\n\n"
        f"**Scan type:** "
        f"{findings_data.get('scan_type', 'Security Audit')}\n\n"
        f"**Source:** "
        f"`{findings_data.get('source', 'unknown')}`\n\n"
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
