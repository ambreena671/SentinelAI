import streamlit as st
import json
import time
from tools.dast_checks import run_dast_scan
from tools.semgrep_tool import run_semgrep_sast
from tools.rag_tool import LightweightRAGTool
from agents.llm_fallback import ResilientLLMClient

st.set_page_config(page_title="CyberSage Security Scanner", page_icon="🛡️", layout="wide")

st.title("🛡️ CyberSage Agentic Security Scanner")
st.caption("Automated SAST, DAST & RAG Remediation Framework")

# Sidebar Controls (Clean: No API Key Inputs)
with st.sidebar:
    st.header("⚙️ Scanner Settings")
    demo_mode = st.toggle("⚡ Demo Fallback Mode", help="Loads pre-captured scan results from OWASP Juice Shop if live target fails.")
    
    st.divider()
    st.markdown("### 🔑 API Status")
    
    # Visual check if secrets are loaded
    groq_ok = "GROQ_API_KEY" in st.secrets or "GROQ_API_KEY" in st.secrets.get("secrets", {}) or False
    gemini_ok = "GEMINI_API_KEY" in st.secrets or "GEMINI_API_KEY" in st.secrets.get("secrets", {}) or False
    
    st.write(f"Groq API Secret: {'✅ Detected' if groq_ok else '⚠️ Not Found'}")
    st.write(f"Gemini API Secret: {'✅ Detected' if gemini_ok else '⚠️ Not Found'}")

# Main Inputs
col1, col2 = st.columns(2)
with col1:
    repo_url = st.text_input("GitHub Repository Directory", placeholder="e.g. ./relative_repo_path")
with col2:
    target_url = st.text_input("Live Target URL", placeholder="http://localhost:3000")

auth_confirmed = st.checkbox("⚠️ I explicitly confirm I own or have permission to scan this target URL.")

st.divider()

if st.button("🚀 Execute Comprehensive Security Scan", type="primary"):
    if not auth_confirmed and not demo_mode:
        st.error("You must confirm target authorization before proceeding.")
        st.stop()
        
    audit_logs = []
    log_box = st.empty()
    
    def log_event(msg: str):
        audit_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        log_box.code("\n".join(audit_logs), language="text")

    rag = LightweightRAGTool()
    
    if demo_mode:
        log_event("[Demo Mode Activated] Loading pre-captured benchmark results...")
        time.sleep(1)
        with open("sample_data/juice_shop_fallback.json") as f:
            findings_data = json.load(f)
    else:
        log_event("[Recon Agent] Target authorized. Initiating active scan...")
        
        # DAST
        dast_results = run_dast_scan(target_url, auth_confirmed, log_callback=log_event) if target_url else {}
        
        # SAST
        sast_results = run_semgrep_sast(repo_url, log_callback=log_event) if repo_url else []
        
        # RAG Guidance Matching
        log_event("[RAG Agent] Matching findings against OWASP & CWE knowledge base...")
        guidance = rag.retrieve_guidance(json.dumps(dast_results) + json.dumps(sast_results))
        
        # Resilient LLM Call
        log_event("[LLM Agent] Generating executive summary & remediation roadmap...")
        llm = ResilientLLMClient()
        llm_summary = llm.generate(
            f"Synthesize these vulnerability findings and RAG guidance into an executive report:\nFindings: {json.dumps(dast_results)}\nSAST: {json.dumps(sast_results)}\nGuidance: {json.dumps(guidance)}"
        )
        
        findings_data = {
            "dast_findings": dast_results,
            "sast_findings": sast_results,
            "rag_guidance": guidance,
            "executive_summary": llm_summary
        }

    st.success("Scan Completed!")
    
    # Render Results
    st.subheader("📋 Executive & Technical Report")
    if "executive_summary" in findings_data:
        st.markdown(findings_data["executive_summary"])
        
    st.subheader("🔎 Raw Finding Details")
    st.json(findings_data)
    
    report_md = f"# CyberSage Security Scan Report\n\n```json\n{json.dumps(findings_data, indent=2)}\n```"
    st.download_button("📥 Download Report (Markdown)", report_md, file_name="security_report.md", mime="text/markdown")