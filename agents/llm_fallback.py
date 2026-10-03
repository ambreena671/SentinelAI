import os
import time
from typing import Optional
import streamlit as st
from groq import Groq
import google.generativeai as genai

class ResilientLLMClient:
    def __init__(self):
        # Read directly from Streamlit Secrets or Environment Variables
        self.groq_key = self._get_secret("GROQ_API_KEY")
        self.gemini_key = self._get_secret("GEMINI_API_KEY")
        
        self.groq_client = None
        if self.groq_key:
            try:
                self.groq_client = Groq(api_key=self.groq_key)
            except Exception:
                pass

        if self.gemini_key:
            try:
                genai.configure(api_key=self.gemini_key)
            except Exception:
                pass

    def _get_secret(self, key_name: str) -> Optional[str]:
        # 1. Try st.secrets
        try:
            if key_name in st.secrets:
                return st.secrets[key_name]
        except Exception:
            pass
        # 2. Try environment variables
        return os.getenv(key_name)

    def generate(self, prompt: str, system_prompt: str = "You are a senior cybersecurity expert.", timeout: int = 30) -> str:
        # 1. Primary: Groq API
        if self.groq_client:
            for _ in range(2):
                try:
                    response = self.groq_client.chat.completions.create(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        model="llama-3.3-70b-versatile",
                        temperature=0.2,
                        timeout=timeout
                    )
                    return response.choices[0].message.content
                except Exception:
                    time.sleep(1)

        # 2. Fallback: Gemini 2.0 Flash API
        if self.gemini_key:
            try:
                model = genai.GenerativeModel("gemini-2.0-flash")
                response = model.generate_content(
                    f"{system_prompt}\n\nTask:\n{prompt}",
                    generation_config={"temperature": 0.2}
                )
                return response.text
            except Exception:
                pass

        # 3. Graceful degradation when both keys/APIs fail
        return "⚠️ LLM temporarily unavailable. Showing raw security findings only without automated reasoning."