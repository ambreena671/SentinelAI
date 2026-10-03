import os
import time
from typing import Optional

import streamlit as st

try:
    from groq import Groq
except Exception:
    Groq = None

try:
    import google.generativeai as genai
except Exception:
    genai = None


class ResilientLLMClient:
    def __init__(self):
        self.groq_key = self._get_secret("GROQ_API_KEY")
        self.gemini_key = self._get_secret("GEMINI_API_KEY")
        self.groq_client = None

        if self.groq_key and Groq:
            try:
                self.groq_client = Groq(api_key=self.groq_key)
            except Exception:
                self.groq_client = None

        if self.gemini_key and genai:
            try:
                genai.configure(api_key=self.gemini_key)
            except Exception:
                pass

    def _get_secret(self, key_name: str) -> Optional[str]:
        try:
            if key_name in st.secrets:
                return st.secrets[key_name]
        except Exception:
            pass
        return os.getenv(key_name)

    def generate(
        self,
        prompt: str,
        system_prompt: str = "You are SentinelAI, a senior defensive application-security expert.",
        timeout: int = 30,
    ) -> str:
        if self.groq_client:
            try:
                response = self.groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    model="llama-3.3-70b-versatile",
                    temperature=0.2,
                    timeout=timeout,
                )
                return response.choices[0].message.content
            except Exception:
                time.sleep(0.5)

        if self.gemini_key and genai:
            try:
                model = genai.GenerativeModel("gemini-2.0-flash")
                response = model.generate_content(
                    f"{system_prompt}\n\nTask:\n{prompt}",
                    generation_config={"temperature": 0.2},
                )
                return response.text
            except Exception:
                pass

        return (
            "AI explanation is unavailable. The static findings above remain valid "
            "as potential issues that require developer review."
        )
