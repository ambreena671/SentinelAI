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

    Groq:
        openai/gpt-oss-20b

    Gemini:
        gemini-2.5-flash
    """

    GROQ_MODEL = "openai/gpt-oss-20b"
    GEMINI_MODEL = "gemini-2.5-flash"

    def __init__(self):
        self.groq_key = self._get_secret("GROQ_API_KEY")
        self.gemini_key = self._get_secret("GEMINI_API_KEY")

        self.groq_client = None

        self.groq_error = None
        self.gemini_error = None

        # =================================================
        # GROQ INITIALIZATION
        # =================================================

        if self.groq_key and Groq:

            try:
                self.groq_client = Groq(
                    api_key=self.groq_key
                )

            except Exception as exc:
                self.groq_error = (
                    f"Groq initialization error: {exc}"
                )

        elif not self.groq_key:

            self.groq_error = (
                "GROQ_API_KEY is not configured."
            )

        elif Groq is None:

            self.groq_error = (
                "Groq API package is not installed."
            )

        # =================================================
        # GEMINI INITIALIZATION
        # =================================================

        if self.gemini_key and genai:

            try:
                genai.configure(
                    api_key=self.gemini_key
                )

            except Exception as exc:
                self.gemini_error = (
                    f"Gemini initialization error: {exc}"
                )

        elif not self.gemini_key:

            self.gemini_error = (
                "GEMINI_API_KEY is not configured."
            )

        elif genai is None:

            self.gemini_error = (
                "Gemini API package is not installed."
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

        # Environment variable fallback
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

            # Compatibility with different SDK versions
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

            # GPT-OSS reasoning configuration.
            # Low reasoning leaves more room for the
            # actual security report.
            reasoning_effort="low",

            # We only need the final security report,
            # not the model's internal reasoning.
            include_reasoning=False,

            temperature=0.2,

            # Increased from 4096 because your previous
            # request ended with finish_reason="length".
            max_completion_tokens=8192,

            stream=False,

            timeout=timeout,
        )

        if response is None:

            raise RuntimeError(
                "Groq returned no response."
            )

        choices = getattr(
            response,
            "choices",
            None
        )

        if not choices:

            raise RuntimeError(
                "Groq returned no choices."
            )

        choice = choices[0]

        message = getattr(
            choice,
            "message",
            None
        )

        if message is None:

            raise RuntimeError(
                "Groq returned no message."
            )

        content = getattr(
            message,
            "content",
            None
        )

        if content:

            return str(content).strip()

        finish_reason = getattr(
            choice,
            "finish_reason",
            None
        )

        if finish_reason:

            raise RuntimeError(
                "Groq returned no text. "
                f"Finish reason: {finish_reason}"
            )

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
                "max_output_tokens": 8192,
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
            "4. Identify the affected file and line when "
            "available.\n"
            "5. Explain why the code is risky.\n"
            "6. Map vulnerabilities to OWASP/CWE when "
            "appropriate.\n"
            "7. Explain potential security impact.\n"
            "8. Describe the attack type at a high level.\n"
            "9. Provide practical remediation.\n"
            "10. If the code does not support a finding, "
            "do not report it.\n"
            "11. Do not provide exploit payloads.\n"
            "12. Do not provide instructions for attacking "
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
