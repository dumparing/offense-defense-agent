"""
sub_agents.py — Hierarchical sub-agents for the security testing framework.

Sub-agents extend SkillBase so they can be registered in the parent agent's
SkillRegistry and selected by the planner like any other skill. Internally,
each sub-agent owns its own SecurityAgent with a private skill set and runs
a mini chain, then returns a synthesized result to the parent.

This implements the hierarchical architecture described in the design docs:

    Parent SecurityAgent
        ├── BinaryAnalysisSubAgent  →  gdb_debug + disassemble chain
        ├── ExploitSubAgent         →  ret2win | heap_exploit | uaf_exploit | format_exploit
        └── ReconSubAgent           →  network_scan

Sub-agents use persist_memory=False so they never overwrite the parent's
persistent memory file. The parent agent replays sub-agent results into its
own MemoryManager after each sub-agent call.

AUTHORIZED TESTING ONLY — for CTF and defensive security research.
"""

from __future__ import annotations

import os
from typing import Any

from core.skill_base import SkillBase
from core.skill_registry import SkillRegistry


# ---------------------------------------------------------------------------
# BinaryAnalysisSubAgent
# ---------------------------------------------------------------------------

class BinaryAnalysisSubAgent(SkillBase):
    """
    Run a full binary analysis chain (gdb_debug → disassemble) and return
    a synthesized vulnerability report.

    Replaces the two-step gdb_debug → disassemble sequence in the parent
    agent with a single skill call. The sub-agent handles orchestration
    internally and returns the combined findings.
    """

    @property
    def name(self) -> str:
        return "binary_analysis"

    @property
    def description(self) -> str:
        return (
            "Run a complete binary analysis chain: debug the binary to find crashes, "
            "then disassemble it to classify the vulnerability and identify dangerous "
            "function calls. Returns a synthesized report with vulnerability class, "
            "crash data, and risk level. Use this as the first step for any binary target."
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
        # Import here to avoid circular import (sub_agents → agent → sub_agents)
        from agent.agent import SecurityAgent
        from skills.gdb_debug import GDBDebugSkill
        from skills.disassemble import DisassembleSkill

        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        binary_path = kwargs["binary_path"]
        if not os.path.isfile(binary_path):
            return {"success": False, "data": None, "error": f"Binary not found: {binary_path}"}

        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())

        agent = SecurityAgent(registry, persist_memory=False)
        chain_result = agent.run_chain(
            f"Analyze the binary at {binary_path} for security vulnerabilities. "
            "Debug it to find crashes and disassemble it to identify dangerous "
            "function calls and vulnerability patterns.",
            context={"binary_path": binary_path},
            max_steps=3,
        )

        memory = chain_result.get("final_memory", {})
        report = chain_result.get("final_report", {})
        vulns = memory.get("vulnerabilities", [])
        vuln_class = _best_vuln_class(vulns, binary_name=os.path.basename(binary_path))

        return {
            "success": True,
            "data": {
                "binary": binary_path,
                "vulnerability_class": vuln_class,
                "crash_data": memory.get("crash_data", []),
                "vulnerabilities": vulns,
                "analyzed_binaries": memory.get("analyzed_binaries", {}),
                "findings": report.get("all_findings", []),
                "steps_taken": chain_result.get("total_steps", 0),
            },
            "error": None,
        }


# ---------------------------------------------------------------------------
# ExploitSubAgent
# ---------------------------------------------------------------------------

class ExploitSubAgent(SkillBase):
    """
    Given a vulnerability class, select and run the correct specific exploit
    skill, then return the exploitation result.

    Selects deterministically from: ret2win (stack BOF), heap_exploit (heap BOF),
    uaf_exploit (use-after-free), format_exploit (format string). The selection
    also accounts for whether the binary name suggests a heap target.
    """

    @property
    def name(self) -> str:
        return "exploit_sub_agent"

    @property
    def description(self) -> str:
        return (
            "Select and run the appropriate exploit skill based on the vulnerability "
            "class identified during binary analysis. Handles: buffer_overflow "
            "(ret2win for stack, heap_exploit for heap), use_after_free (uaf_exploit), "
            "format_string (format_exploit). Run AFTER binary_analysis."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "binary_path": {
                "type": "str",
                "description": "Path to the vulnerable binary",
            },
            "vulnerability_class": {
                "type": "str",
                "description": "buffer_overflow, use_after_free, or format_string",
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        from agent.agent import SecurityAgent
        from skills.ret2win import Ret2WinSkill
        from skills.heap_exploit import HeapExploitSkill
        from skills.uaf_exploit import UAFExploitSkill
        from skills.format_exploit import FormatExploitSkill

        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        binary_path = kwargs["binary_path"]
        vuln_class = kwargs["vulnerability_class"]
        binary_name = os.path.basename(binary_path)

        # Select the right exploit skill
        skill_name = _select_exploit_skill(vuln_class, binary_name)

        registry = SkillRegistry()
        registry.register(Ret2WinSkill())
        registry.register(HeapExploitSkill())
        registry.register(UAFExploitSkill())
        registry.register(FormatExploitSkill())

        skill = registry.get(skill_name)
        if skill is None:
            return {
                "success": False,
                "data": None,
                "error": f"No exploit skill available for: {vuln_class}",
            }

        result = skill.execute(binary_path=binary_path)

        # Propagate sub-agent identity into the data for memory tracking
        if result.get("data"):
            result["data"]["exploit_skill_used"] = skill_name

        return result


# ---------------------------------------------------------------------------
# ReconSubAgent
# ---------------------------------------------------------------------------

class ReconSubAgent(SkillBase):
    """
    Run network reconnaissance (nmap scan) on a target and return a
    structured recon report.

    Wraps NetworkScanSkill in a sub-agent so it fits the hierarchical
    architecture pattern consistently with BinaryAnalysisSubAgent and
    ExploitSubAgent.
    """

    @property
    def name(self) -> str:
        return "recon"

    @property
    def description(self) -> str:
        return (
            "Run a network scan (nmap -sV) on a target IP and return a "
            "structured recon report with open ports, services, and versions. "
            "Use as the first step for network-based targets."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "target_ip": {
                "type": "str",
                "description": "IPv4 address of the target host",
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        from agent.agent import SecurityAgent
        from skills.network_scan import NetworkScanSkill

        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        registry = SkillRegistry()
        registry.register(NetworkScanSkill())

        agent = SecurityAgent(registry, persist_memory=False)
        result = agent.run(
            f"Scan {kwargs['target_ip']} for open services",
            context={"target_ip": kwargs["target_ip"]},
        )

        return {
            "success": result.get("success", False),
            "data": (result.get("skill_result") or {}).get("data"),
            "error": None,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Vulnerability class priority — more specific/exploitable types first
_VULN_PRIORITY = ["use_after_free", "buffer_overflow", "format_string"]


def _best_vuln_class(vulns: list[dict], binary_name: str = "") -> str:
    """
    Return the most exploitable vulnerability class from a list.

    Uses binary_name as a strong hint when the name encodes the vuln type
    (e.g. vuln_heap → buffer_overflow, vuln_uaf → use_after_free). This
    prevents false-positive UAF labels on heap-overflow binaries that use
    malloc/free internally.
    """
    found = {v.get("vulnerability", "") for v in vulns}
    # Binary name takes priority — these targets have descriptive names
    if binary_name:
        if ("bof" in binary_name or "heap" in binary_name) and "buffer_overflow" in found:
            return "buffer_overflow"
        if "uaf" in binary_name and "use_after_free" in found:
            return "use_after_free"
        if "fmt" in binary_name and "format_string" in found:
            return "format_string"
    # Fallback: priority order
    for priority in _VULN_PRIORITY:
        if priority in found:
            return priority
    return vulns[0].get("vulnerability", "unknown") if vulns else "unknown"


def _select_exploit_skill(vuln_class: str, binary_name: str) -> str:
    """Pick the right exploit skill name based on vulnerability class and binary name."""
    if vuln_class == "buffer_overflow":
        # Heap overflow targets have 'heap' in their name
        return "heap_exploit" if "heap" in binary_name else "ret2win"
    elif vuln_class == "use_after_free":
        return "uaf_exploit"
    elif vuln_class == "format_string":
        return "format_exploit"
    else:
        return "ret2win"
