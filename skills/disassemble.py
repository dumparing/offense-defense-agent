"""
disassemble.py — Skill: disassemble and analyze a binary for vulnerabilities.

Performs static analysis on a binary to identify:
    - Buffer overflow primitives (gets, strcpy, sprintf)
    - Format string vulnerabilities (user-controlled printf args)
    - Use-after-free patterns (malloc/free lifecycle issues)
    - Binary protections (NX, PIE, RELRO, stack canaries)

This skill is typically used after gdb_debug has confirmed a crash,
to understand the root cause vulnerability class.

Flow:
    Agent → DisassembleSkill.execute(binary_path="...")
          → tools.disassembler.disassemble_binary()
          → tools.disassembler.get_binary_info()
          → tools.disassembler.get_strings()
          → structured vulnerability analysis returned to agent
"""

from __future__ import annotations

from typing import Any

from core.skill_base import SkillBase
from tools.disassembler import (
    disassemble_binary,
    get_binary_info,
    get_strings,
)


class DisassembleSkill(SkillBase):
    """Disassemble and analyze a binary for memory corruption vulnerabilities."""

    @property
    def name(self) -> str:
        return "disassemble"

    @property
    def description(self) -> str:
        return (
            "Disassemble a binary and analyze it for memory corruption "
            "vulnerabilities: buffer overflows, format strings, use-after-free. "
            "Also reports binary protections (NX, PIE, RELRO). "
            "Use after gdb_debug confirms a crash to classify the vulnerability."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "binary_path": {
                "type": "str",
                "description": "Path to the binary to analyze",
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        """Run full binary analysis: disassemble + info + strings."""
        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        binary_path = kwargs["binary_path"]

        # Step 1: Get binary metadata (arch, protections)
        binary_info = get_binary_info(binary_path)

        # Step 2: Disassemble and find dangerous patterns
        disasm_result = disassemble_binary(binary_path)

        if disasm_result["error"]:
            return {
                "success": False,
                "data": {"binary_info": binary_info},
                "error": disasm_result["error"],
            }

        # Step 3: Extract strings for additional context
        strings_result = get_strings(binary_path)

        # Step 4: Build comprehensive vulnerability report
        vuln_report = self._build_vuln_report(
            binary_path, binary_info, disasm_result, strings_result
        )

        return {
            "success": True,
            "data": vuln_report,
            "error": None,
        }

    def _build_vuln_report(
        self,
        binary_path: str,
        binary_info: dict,
        disasm_result: dict,
        strings_result: dict,
    ) -> dict[str, Any]:
        """Build a comprehensive vulnerability analysis report."""

        functions = disasm_result.get("functions", [])
        dangerous_calls = disasm_result.get("dangerous_calls", [])
        vuln_patterns = disasm_result.get("vulnerability_patterns", [])
        sections = disasm_result.get("sections", [])
        interesting_strings = strings_result.get("interesting_strings", [])

        # Determine overall risk level
        risk_level = self._assess_risk(binary_info, vuln_patterns)

        # Protection analysis
        protections = {
            "nx": binary_info.get("nx"),
            "pie": binary_info.get("pie"),
            "relro": binary_info.get("relro"),
            "stripped": binary_info.get("stripped"),
        }

        # Count missing protections
        missing_protections = []
        if not binary_info.get("nx"):
            missing_protections.append("NX (stack is executable)")
        if not binary_info.get("pie"):
            missing_protections.append("PIE (no ASLR for binary)")
        if binary_info.get("relro") == "none":
            missing_protections.append("RELRO (GOT is writable)")
        if not binary_info.get("stripped"):
            missing_protections.append("Not stripped (symbols available)")

        return {
            "binary": binary_path,
            "architecture": {
                "arch": binary_info.get("arch"),
                "bits": binary_info.get("bits"),
                "endian": binary_info.get("endian"),
            },
            "protections": protections,
            "missing_protections": missing_protections,
            "functions_found": len(functions),
            "function_list": [f["name"] for f in functions[:30]],
            "dangerous_calls": dangerous_calls,
            "vulnerability_patterns": vuln_patterns,
            "interesting_strings": interesting_strings[:20],
            "sections": sections,
            "risk_level": risk_level,
        }

    @staticmethod
    def _assess_risk(
        binary_info: dict,
        vuln_patterns: list[dict],
    ) -> str:
        """Assess overall risk based on vulnerabilities and protections."""
        score = 0

        # Vulnerability patterns
        for pattern in vuln_patterns:
            conf = pattern.get("confidence", "low")
            if conf == "high":
                score += 3
            elif conf == "medium":
                score += 2
            else:
                score += 1

        # Missing protections increase exploitability
        if not binary_info.get("nx"):
            score += 2  # Executable stack
        if not binary_info.get("pie"):
            score += 1  # No ASLR
        if binary_info.get("relro") == "none":
            score += 1  # Writable GOT

        if score >= 5:
            return "critical"
        elif score >= 3:
            return "high"
        elif score >= 1:
            return "medium"
        return "low"
