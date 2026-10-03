import json
import os
import math
from collections import Counter
from typing import List, Dict, Any

class LightweightRAGTool:
    def __init__(self, knowledge_base_path: str = "rag_data/owasp_cwe_knowledge.json"):
        self.documents = []
        self.vocabulary = set()
        self.doc_vectors = []
        self.load_knowledge_base(knowledge_base_path)

    def _tokenize(self, text: str) -> List[str]:
        return [word.lower() for word in text.replace("-", " ").replace("_", " ").split() if word.isalnum()]

    def load_knowledge_base(self, path: str):
        if not os.path.exists(path):
            return
        
        with open(path, "r", encoding="utf-8") as f:
            self.documents = json.load(f)

        # Build vocabulary & simple TF vectors
        for doc in self.documents:
            content = f"{doc['id']} {doc['name']} {doc['description']} {doc['remediation']}"
            tokens = self._tokenize(content)
            tf = Counter(tokens)
            self.doc_vectors.append((doc, tf))
            self.vocabulary.update(tokens)

    def retrieve_guidance(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        if not self.doc_vectors:
            return []

        query_tokens = self._tokenize(query)
        query_tf = Counter(query_tokens)

        scored_docs = []
        for doc, doc_tf in self.doc_vectors:
            # Calculate cosine similarity score
            intersection = set(query_tf.keys()) & set(doc_tf.keys())
            dot_product = sum(query_tf[token] * doc_tf[token] for token in intersection)
            
            query_magnitude = math.sqrt(sum(val ** 2 for val in query_tf.values()))
            doc_magnitude = math.sqrt(sum(val ** 2 for val in doc_tf.values()))
            
            if query_magnitude == 0 or doc_magnitude == 0:
                similarity = 0.0
            else:
                similarity = dot_product / (query_magnitude * doc_magnitude)

            scored_docs.append((similarity, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored_docs[:top_k] if score > 0.05]