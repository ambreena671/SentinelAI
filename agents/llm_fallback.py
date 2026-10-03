import os
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
        self.groq_error = None
        self.gemini_error = None

        # -------------------------
        # Initialize Groq
        # -------------------------
        if self.groq_key and Groq:
            try:
                self.groq_client = Groq(api_key=self.groq_key)
            except Exception as exc:
                self.groq_error = f"Groq initialization error: {exc}"

        # -------------------------
        # Initialize Gemini
        # -------------------------
        if self.gemini_key and genai:
            try:
                genai.configure(api_key=self.gemini_key)
            except Exception as exc:
                self.gemini_error = f"Gemini initialization error: {exc}"

    def _get_secret(self, key_name: str) -> Optional[str]:
        """
        Read API key from Streamlit secrets first,
        then fall back to environment variables.
        """

        try:
            value = st.secrets.get(key_name)

            if value:
                return str(value).strip()

        except Exception:
            pass

        value = os.getenv(key_name)

        if value:
            return value.strip()

        return None

    def generate(
        self,
        prompt: str,
        system_prompt: str = (
            "You are SentinelAI, a senior defensive "
            "application-security expert. "
            "Analyze source code for security weaknesses. "
            "Do not invent vulnerabilities. "
            "Explain evidence, security impact, possible attack "
            "type, and remediation."
        ),
        timeout: int = 30,
    ) -> str:

        errors = []

        # =====================================================
        # 1. Try Groq
        # =====================================================

        if self.groq_client:

            try:
                response = self.groq_client.chat.completions.create(
                    messages=[
                        {
                            "role": "system",
                            "content": system_prompt,
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],

                    # Current commonly available Groq model.
                    model="llama-3.1-8b-instant",

                    temperature=0.2,

                    timeout=timeout,
                )

                content = response.choices[0].message.content

                if content:
                    return content.strip()

                errors.append("Groq returned an empty response.")

            except Exception as exc:
                errors.append(f"Groq error: {exc}")

        elif self.groq_key and Groq is None:
            errors.append(
                "Groq API package is not installed."
            )

        elif not self.groq_key:
            errors.append(
                "GROQ_API_KEY is not configured."
            )

        if self.groq_error:
            errors.append(self.groq_error)

        # =====================================================
        # 2. Try Gemini
        # =====================================================

        if self.gemini_key and genai:

            try:
                model = genai.GenerativeModel(
                    "gemini-3.8-flash"
                )

                response = model.generate_content(
                    f"{system_prompt}\n\n"
                    f"Task:\n{prompt}",
                    generation_config={
                        "temperature": 0.2,
                    },
                )

                text = getattr(response, "text", None)

                if text:
                    return text.strip()

                errors.append(
                    "Gemini returned an empty response."
                )

            except Exception as exc:
                errors.append(
                    f"Gemini error: {exc}"
                )

        elif self.gemini_key and genai is None:
            errors.append(
                "Gemini API package is not installed."
            )

        elif not self.gemini_key:
            errors.append(
                "GEMINI_API_KEY is not configured."
            )

        if self.gemini_error:
            errors.append(self.gemini_error)

        # =====================================================
        # 3. Show useful diagnostic information
        # =====================================================

        diagnostic = "\n".join(
            f"- {error}" for error in errors
        )

        return (
            "AI explanation is unavailable.\n\n"
            "The static security findings remain valid "
            "as potential issues requiring developer review.\n\n"
            "### AI connection diagnostics\n"
            f"{diagnostic}"
        )
