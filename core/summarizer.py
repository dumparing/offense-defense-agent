"""
summarizer.py — Compress raw tool output into concise findings.

After each skill execution the summarizer:
    1. Sends raw output to the local Llama model for natural-language summary.
    2. Extracts structured findings (ports, services, observations).
    3. Returns both so the memory manager can store them compactly.

If the LLM is unavailable, falls back to a simple rule-based extraction
so the pipeline never breaks.

Safety:
    - The summarizer must NOT fabricate vulnerabilities that were not observed.
    - It may suggest benign next steps for authorized defensive testing only.
"""

from __future__ import annotations

from typing import Any

from core.llm_client import LLMClient, OllamaError


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SUMMARIZER_SYSTEM = (
    "You are a cybersecurity analyst summarizing tool output for a defensive "
    "security assessment. Be concise and factual. Do NOT fabricate findings "
    "that are not present in the data. Do NOT suggest exploitation. "
    "Focus on: what was discovered, what services are running, and what "
    "an authorized tester should note."
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Summarizer:
    """Compress skill output into summaries and structured findings."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def summarize_scan(self, skill_result: dict[str, Any]) -> dict[str, Any]:
        """
        Summarize a network_scan skill result.

        Returns:
            {
                "natural_language_summary": str,
                "structured": {
                    "open_ports": [int, ...],
                    "services": {"port": "service_name", ...},
                    "findings": [str, ...]
                }
            }
        """
        data = skill_result.get("data", {})
        services_list = data.get("services", [])
        target = data.get("target", "unknown")

        # Try LLM-based summarization first
        try:
            return self._llm_summarize_scan(target, services_list, data)
        except OllamaError:
            # Fallback to rule-based extraction
            return self._fallback_summarize_scan(target, services_list)

    def summarize_gdb(self, skill_result: dict[str, Any]) -> dict[str, Any]:
        """Summarize GDB debug skill results."""
        data = skill_result.get("data", {})
        crashes = data.get("crashes", [])
        any_crash = data.get("any_crash", False)
        binary = data.get("binary", "unknown")
        indicators = data.get("vulnerability_indicators", [])

        # Build summary even without LLM
        if not any_crash:
            return {
                "natural_language_summary": (
                    f"GDB analysis of {binary}: no crashes detected across "
                    f"{data.get('total_tests', 0)} test inputs."
                ),
                "structured": {
                    "crashed": False,
                    "findings": [f"No crashes found in {binary}."],
                },
            }

        crash_summaries = []
        for crash in crashes:
            sig = crash.get("signal", "unknown")
            addr = crash.get("fault_address", "unknown")
            label = crash.get("input_label", "unknown")
            crash_summaries.append(
                f"Crash with {sig} at {addr} (input: {label})"
            )

        findings = crash_summaries + [
            f"Vulnerability indicators: {', '.join(indicators)}"
        ] if indicators else crash_summaries

        try:
            return self._llm_summarize_generic("gdb_debug", skill_result)
        except OllamaError:
            return {
                "natural_language_summary": (
                    f"GDB analysis of {binary}: found {len(crashes)} crash(es) "
                    f"across {data.get('total_tests', 0)} test inputs. "
                    f"Signals: {', '.join(set(c.get('signal', '?') for c in crashes))}. "
                    f"Indicators: {', '.join(indicators)}."
                ),
                "structured": {
                    "crashed": True,
                    "crash_count": len(crashes),
                    "signals": list(set(c.get("signal") for c in crashes)),
                    "indicators": indicators,
                    "findings": findings,
                },
            }

    def summarize_disassembly(self, skill_result: dict[str, Any]) -> dict[str, Any]:
        """Summarize disassembly analysis results."""
        data = skill_result.get("data", {})
        binary = data.get("binary", "unknown")
        vuln_patterns = data.get("vulnerability_patterns", [])
        dangerous_calls = data.get("dangerous_calls", [])
        risk_level = data.get("risk_level", "unknown")
        missing_protections = data.get("missing_protections", [])

        findings = []
        for pattern in vuln_patterns:
            findings.append(
                f"{pattern['vulnerability']} ({pattern['confidence']} confidence): "
                f"{pattern['description']}"
            )
        if missing_protections:
            findings.append(
                f"Missing protections: {', '.join(missing_protections)}"
            )

        try:
            return self._llm_summarize_generic("disassemble", skill_result)
        except OllamaError:
            return {
                "natural_language_summary": (
                    f"Disassembly of {binary}: risk level {risk_level}. "
                    f"Found {len(dangerous_calls)} dangerous call(s) and "
                    f"{len(vuln_patterns)} vulnerability pattern(s). "
                    f"Missing protections: {', '.join(missing_protections) or 'none'}."
                ),
                "structured": {
                    "risk_level": risk_level,
                    "vulnerability_patterns": vuln_patterns,
                    "dangerous_calls_count": len(dangerous_calls),
                    "missing_protections": missing_protections,
                    "findings": findings,
                },
            }

    def summarize_generic(self, skill_name: str, skill_result: dict[str, Any]) -> dict[str, Any]:
        """
        Generic summarization for any skill result.

        Routes to skill-specific summarizers when available,
        otherwise does a generic LLM summary.
        """
        if skill_name == "network_scan" and skill_result.get("success"):
            return self.summarize_scan(skill_result)

        if skill_name == "gdb_debug" and skill_result.get("success"):
            return self.summarize_gdb(skill_result)

        if skill_name == "disassemble" and skill_result.get("success"):
            return self.summarize_disassembly(skill_result)

        # Generic path
        try:
            return self._llm_summarize_generic(skill_name, skill_result)
        except OllamaError:
            return {
                "natural_language_summary": (
                    f"Skill '{skill_name}' completed. "
                    f"Success: {skill_result.get('success', False)}."
                ),
                "structured": {
                    "findings": [f"{skill_name} execution recorded."],
                },
            }

    # ------------------------------------------------------------------
    # LLM-based summarization
    # ------------------------------------------------------------------

    def _llm_summarize_scan(
        self, target: str, services: list[dict], data: dict
    ) -> dict[str, Any]:
        """Use the local LLM to summarize scan results."""

        # Build a concise text representation for the LLM
        svc_lines = []
        for s in services:
            svc_lines.append(
                f"  {s['port']}/{s['protocol']} {s['state']} "
                f"{s['service']} {s.get('version', '')}"
            )
        svc_text = "\n".join(svc_lines) if svc_lines else "  No services found."

        prompt = (
            f"Summarize these nmap scan results for target {target}.\n\n"
            f"Services discovered:\n{svc_text}\n\n"
            "Respond with ONLY valid JSON in this exact format:\n"
            "{\n"
            '  "summary": "One paragraph natural language summary",\n'
            '  "open_ports": [list of open port numbers as integers],\n'
            '  "services": {"port_number": "service_name", ...},\n'
            '  "findings": ["finding 1", "finding 2"]\n'
            "}\n\n"
            "Rules:\n"
            "- Only report what is actually in the data\n"
            "- Do NOT fabricate vulnerabilities\n"
            "- Keep findings factual and concise\n"
        )

        result = self.llm.generate_json(prompt, system_prompt=SUMMARIZER_SYSTEM)

        return {
            "natural_language_summary": result.get("summary", "Scan completed."),
            "structured": {
                "open_ports": result.get("open_ports", []),
                "services": result.get("services", {}),
                "findings": result.get("findings", []),
            },
        }

    def _llm_summarize_generic(
        self, skill_name: str, skill_result: dict[str, Any]
    ) -> dict[str, Any]:
        """Generic LLM summarization for any skill."""
        # Truncate data to avoid blowing up the prompt
        result_str = str(skill_result)[:2000]

        prompt = (
            f"Summarize the output of the '{skill_name}' security tool.\n\n"
            f"Result:\n{result_str}\n\n"
            "Respond with ONLY valid JSON:\n"
            "{\n"
            '  "summary": "Concise natural language summary",\n'
            '  "findings": ["key finding 1", "key finding 2"]\n'
            "}\n"
        )

        result = self.llm.generate_json(prompt, system_prompt=SUMMARIZER_SYSTEM)

        return {
            "natural_language_summary": result.get("summary", "Completed."),
            "structured": {
                "findings": result.get("findings", []),
            },
        }

    # ------------------------------------------------------------------
    # Fallback (no LLM available)
    # ------------------------------------------------------------------

    @staticmethod
    def _fallback_summarize_scan(
        target: str, services: list[dict]
    ) -> dict[str, Any]:
        """
        Rule-based fallback when the LLM is unavailable.
        Extracts structured data directly from the parsed nmap output.
        """
        open_ports = []
        svc_map = {}
        findings = []

        for s in services:
            if s.get("state") == "open":
                port = s["port"]
                open_ports.append(port)
                svc_map[str(port)] = s["service"]

        if open_ports:
            findings.append(
                f"Found {len(open_ports)} open port(s) on {target}: "
                f"{', '.join(str(p) for p in open_ports)}"
            )
        else:
            findings.append(f"No open ports detected on {target}.")

        summary = (
            f"Scan of {target} discovered {len(open_ports)} open port(s). "
            f"Services: {', '.join(f'{p}/{n}' for p, n in svc_map.items())}."
            if svc_map
            else f"Scan of {target} found no open services."
        )

        return {
            "natural_language_summary": summary,
            "structured": {
                "open_ports": open_ports,
                "services": svc_map,
                "findings": findings,
            },
        }
