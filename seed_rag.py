from pathlib import Path
import json

p = Path("rag_data/owasp_cwe_knowledge.json")
print(f"Knowledge base: {p} ({len(json.loads(p.read_text()))} entries)")
