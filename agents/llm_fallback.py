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
    """
    SentinelAI AI client.

    Provider order:
    1. Groq
    2. Gemini

    The source code is sent to the AI for defensive
    security analysis. The AI must not invent findings.
    """

    GROQ_MODEL = "openai/gpt-oss-20b"
    GEMINI_MODEL = "gemini-3.8-flash"

    def __init__(self):
        self.groq_key = self._get_secret("GROQ_API_KEY")
        self.gemini_key = self._get_secret("GEMINI_API_KEY")

        self.groq_client = None

        self.groq_error = None
        self.gemini_error = None

        # -----------------------------------------
        # Initialize Groq
        # -----------------------------------------
        if self.groq_key and Groq:

            try:
                self.groq_client = Groq(
                    api_key=self.groq_key
                )

            except Exception as exc:
                self.groq_error = (
                    f"Groq initialization error: {exc}"
                )

        elif self.groq_key and Groq is None:

            self.groq_error = (
                "Groq API package is not installed."
            )

        elif not self.groq_key:

            self.groq_error = (
                "GROQ_API_KEY is not configured."
            )

        # -----------------------------------------
        # Initialize Gemini
        # -----------------------------------------
        if self.gemini_key and genai:

            try:
                genai.configure(
                    api_key=self.gemini_key
                )

            except Exception as exc:
                self.gemini_error = (
                    f"Gemini initialization error: {exc}"
                )

        elif self.gemini_key and genai is None:

            self.gemini_error = (
                "Gemini API package is not installed."
            )

        elif not self.gemini_key:

            self.gemini_error = (
                "GEMINI_API_KEY is not configured."
            )

    # =====================================================
    # SECRET LOADING
    # =====================================================

    def _get_secret(
        self,
        key_name: str
    ) -> Optional[str]:

        # Streamlit secrets
        try:
            value = st.secrets.get(key_name)

            if value:
                return str(value).strip()

        except Exception:
            pass

        # Environment variables
        value = os.getenv(key_name)

        if value:
            return value.strip()

        return None

    # =====================================================
    # GROQ RESPONSE EXTRACTION
    # =====================================================

    def _extract_groq_text(self, response):

        if response is None:
            return None

        try:
            choices = getattr(
                response,
                "choices",
                None
            )

            if not choices:
                return None

            choice = choices[0]

            message = getattr(
                choice,
                "message",
                None
            )

            if message is None:
                return None

            content = getattr(
                message,
                "content",
                None
            )

            if content:
                return str(content).strip()

            # Some SDK versions expose model_dump()
            if hasattr(message, "model_dump"):

                data = message.model_dump()

                content = data.get("content")

                if content:
                    return str(content).strip()

                text = data.get("text")

                if text:
                    return str(text).strip()

        except Exception:
            return None

        return None

    # =====================================================
    # GROQ REQUEST
    # =====================================================

    def _call_groq(
        self,
        prompt: str,
        system_prompt: str,
        timeout: int
    ) -> str:

        if not self.groq_client:
            raise RuntimeError(
                "Groq client is not initialized."
            )

        response = self.groq_client.chat.completions.create(
            model=self.GROQ_MODEL,
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
            temperature=0.2,
            max_completion_tokens=4096,
            timeout=timeout,
        )

        text = self._extract_groq_text(response)

        if text:
            return text

        # Try to determine why there was no content
        try:

            if hasattr(response, "model_dump"):

                data = response.model_dump()

                choices = data.get(
                    "choices",
                    []
                )

                if choices:

                    finish_reason = choices[0].get(
                        "finish_reason"
                    )

                    if finish_reason:

                        raise RuntimeError(
                            "Groq returned no text. "
                            f"Finish reason: {finish_reason}"
                        )

        except RuntimeError:
            raise

        except Exception:
            pass

        raise RuntimeError(
            "Groq returned an empty response."
        )

    # =====================================================
    # GEMINI REQUEST
    # =====================================================

    def _call_gemini(
        self,
        prompt: str,
        system_prompt: str
    ) -> str:

        if not self.gemini_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured."
            )

        if genai is None:
            raise RuntimeError(
                "Gemini API package is not installed."
            )

        model = genai.GenerativeModel(
            self.GEMINI_MODEL
        )

        response = model.generate_content(
            f"{system_prompt}\n\n"
            f"Task:\n{prompt}",
            generation_config={
                "temperature": 0.2,
            },
        )

        text = getattr(
            response,
            "text",
            None
        )

        if text:
            return text.strip()

        raise RuntimeError(
            "Gemini returned an empty response."
        )

    # =====================================================
    # MAIN GENERATE FUNCTION
    # =====================================================

    def generate(
        self,
        prompt: str,
        system_prompt: str = (
            "You are SentinelAI, a senior defensive "
            "application-security expert.\n\n"

            "Analyze the supplied source code for "
            "potential security weaknesses.\n\n"

            "Rules:\n"
            "1. Do not invent vulnerabilities.\n"
            "2. Only report issues supported by the "
            "actual source code.\n"
            "3. Explain the exact code evidence.\n"
            "4. Explain why the code is risky.\n"
            "5. Map vulnerabilities to OWASP/CWE when "
            "appropriate.\n"
            "6. Explain potential security impact.\n"
            "7. Describe the attack type at a high level.\n"
            "8. Provide practical remediation.\n"
            "9. Do not provide exploit payloads.\n"
            "10. Do not provide instructions for attacking "
            "real systems.\n"
        ),
        timeout: int = 45,
    ) -> str:

        errors = []

        # =================================================
        # PROVIDER 1 — GROQ
        # =================================================

        if self.groq_client:

            try:

                result = self._call_groq(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    timeout=timeout,
                )

                if result:
                    return result

            except Exception as exc:

                errors.append(
                    f"Groq error: {exc}"
                )

        else:

            if self.groq_error:
                errors.append(
                    self.groq_error
                )

        # =================================================
        # PROVIDER 2 — GEMINI
        # =================================================

        if self.gemini_key and genai:

            try:

                result = self._call_gemini(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )

                if result:
                    return result

            except Exception as exc:

                errors.append(
                    f"Gemini error: {exc}"
                )

        else:

            if self.gemini_error:
                errors.append(
                    self.gemini_error
                )

        # =================================================
        # BOTH PROVIDERS FAILED
        # =================================================

        if not errors:
            errors.append(
                "No AI provider is configured."
            )

        diagnostic = "\n".join(
            f"- {error}"
            for error in errors
        )

        return (
            "AI explanation is unavailable.\n\n"

            "The static security findings remain valid "
            "as potential issues requiring developer review.\n\n"

            "### AI connection diagnostics\n\n"

            f"{diagnostic}"
        )
