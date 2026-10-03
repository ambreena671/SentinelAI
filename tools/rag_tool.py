import json
import math
import os
import re
from collections import Counter
from typing import Any, Dict, List

class LightweightRAGTool:
    def __init__(self, knowledge_base_path: str = "rag_data/owasp_cwe_knowledge.json"):
        self.documents = []
        self.doc_vectors = []
        self.load_knowledge_base(knowledge_base_path)

    def _tokenize(self, text: str) -> List[str]:
        return [
            word.lower()
            for word in re.findall(r"[a-zA-Z0-9]+", text.replace("-", " ").replace("_", " "))
        ]

    def load_knowledge_base(self, path: str):
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            self.documents = json.load(f)
        for doc in self.documents:
            content = " ".join(
                str(doc.get(k, "")) for k in
                ["id", "name", "description", "attack_type", "impact", "remediation"]
            )
            self.doc_vectors.append((doc, Counter(self._tokenize(content))))

    def retrieve_guidance(self, query: str, top_k: int = 6) -> List[Dict[str, Any]]:
        if not self.doc_vectors:
            return []
        query_tf = Counter(self._tokenize(query))
        scored = []
        qmag = math.sqrt(sum(v * v for v in query_tf.values()))
        for doc, tf in self.doc_vectors:
            common = set(query_tf) & set(tf)
            dot = sum(query_tf[t] * tf[t] for t in common)
            dmag = math.sqrt(sum(v * v for v in tf.values()))
            score = dot / (qmag * dmag) if qmag and dmag else 0.0
            scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored[:top_k] if score > 0.03]
