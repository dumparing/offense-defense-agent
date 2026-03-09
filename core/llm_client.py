"""
llm_client.py — Wrapper for local Llama models via Ollama.

Provides two main methods:
    generate_text()  — free-form text completion
    generate_json()  — text completion with JSON parsing and retry

Connects to the Ollama HTTP API at http://localhost:11434.
The model is configurable via the OLLAMA_MODEL environment variable
(default: "llama3:8b").

Why local?
    - No data leaves the machine (critical for security-sensitive outputs)
    - No API keys or billing required
    - Full control over the model and its context
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "llama3:8b"
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)

# Timeout for HTTP requests to Ollama (seconds)
REQUEST_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OllamaError(Exception):
    """Base exception for Ollama-related errors."""


class OllamaConnectionError(OllamaError):
    """Raised when Ollama is not reachable."""


class OllamaModelNotFoundError(OllamaError):
    """Raised when the requested model is not available."""


class OllamaJSONError(OllamaError):
    """Raised when the model output cannot be parsed as JSON."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Thin client for the Ollama /api/generate endpoint.

    Usage:
        client = LLMClient()
        text = client.generate_text("Summarize this scan output: ...")
        data = client.generate_json("Return JSON: {\"skill\": ...}")
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self.model = model or OLLAMA_MODEL
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_text(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> str:
        """
        Generate free-form text from the local Llama model.

        Args:
            prompt:        The user/task prompt.
            system_prompt: Optional system-level instruction.

        Returns:
            The model's text response (stripped of leading/trailing whitespace).

        Raises:
            OllamaConnectionError:   If Ollama is not running.
            OllamaModelNotFoundError: If the model is not pulled.
        """
        return self._call_generate(prompt, system_prompt)

    def generate_json(
        self,
        prompt: str,
        system_prompt: str | None = None,
        retries: int = 1,
    ) -> dict[str, Any]:
        """
        Generate a response and parse it as JSON.

        The prompt should instruct the model to respond with valid JSON.
        If the first attempt fails to parse, we retry with an explicit
        correction prompt up to `retries` additional times.

        Args:
            prompt:        The user/task prompt (should ask for JSON output).
            system_prompt: Optional system-level instruction.
            retries:       Number of retry attempts on parse failure.

        Returns:
            Parsed JSON dict.

        Raises:
            OllamaJSONError: If JSON parsing fails after all retries.
        """
        raw = self._call_generate(prompt, system_prompt)
        parsed = self._try_parse_json(raw)
        if parsed is not None:
            return parsed

        # Retry with explicit correction
        for attempt in range(retries):
            correction = (
                "Your previous response was not valid JSON. "
                "Please respond with ONLY a valid JSON object, no markdown, "
                "no explanation, no code fences. Just the raw JSON.\n\n"
                f"Original prompt:\n{prompt}"
            )
            raw = self._call_generate(correction, system_prompt)
            parsed = self._try_parse_json(raw)
            if parsed is not None:
                return parsed

        raise OllamaJSONError(
            f"Failed to parse model output as JSON after {retries + 1} attempts. "
            f"Last raw output:\n{raw[:500]}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_generate(
        self, prompt: str, system_prompt: str | None
    ) -> str:
        """Send a request to Ollama's /api/generate endpoint."""
        url = f"{self.base_url}/api/generate"

        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise OllamaConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                f"Is Ollama running? (`ollama serve`)\n"
                f"Details: {exc}"
            ) from exc
        except TimeoutError as exc:
            raise OllamaConnectionError(
                f"Request to Ollama timed out after {self.timeout}s."
            ) from exc

        # Check for model-not-found errors in the response
        if "error" in body:
            error_msg = body["error"]
            if "not found" in error_msg.lower():
                raise OllamaModelNotFoundError(
                    f"Model '{self.model}' not found. "
                    f"Pull it with: ollama pull {self.model}"
                )
            raise OllamaError(f"Ollama API error: {error_msg}")

        return body.get("response", "").strip()

    @staticmethod
    def _try_parse_json(text: str) -> dict[str, Any] | None:
        """
        Attempt to parse JSON from model output.

        Handles common LLM quirks:
            - JSON wrapped in ```json ... ``` code fences
            - Leading/trailing whitespace or prose
        """
        # Strip markdown code fences if present
        cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip())
        cleaned = re.sub(r"\s*```$", "", cleaned)

        # Try direct parse
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Try to find a JSON object in the text
        match = re.search(r"\{[\s\S]*\}", cleaned)
        if match:
            try:
                result = json.loads(match.group())
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        return None

    def __repr__(self) -> str:
        return f"<LLMClient model={self.model!r} url={self.base_url!r}>"
