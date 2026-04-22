#!/usr/bin/env python3
"""
risk_analysis.py — Safety and risk analysis for autonomous offensive agents.

This module provides a structured framework for analyzing the risks,
failure modes, and ethical implications of LLM-driven security agents.

It implements:
    1. Guardrail checks — runtime validation before skill execution
    2. Risk taxonomy    — categorized failure modes with severity
    3. Audit logging    — immutable record of all agent decisions
    4. Safety report    — printable analysis for presentations

This is both a functional safety layer AND a research artifact documenting
the risks of autonomous offensive tooling.

Usage:
    python safety/risk_analysis.py              # print full risk report
    python safety/risk_analysis.py --json       # machine-readable output
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Risk taxonomy
# ---------------------------------------------------------------------------

@dataclass
class RiskEntry:
    """A single risk in the taxonomy."""
    id: str
    category: str
    title: str
    description: str
    severity: str           # critical, high, medium, low
    likelihood: str         # high, medium, low
    impact: str             # what happens if this risk materializes
    mitigation: str         # how the system addresses it
    residual_risk: str      # what risk remains after mitigation


RISK_TAXONOMY: list[RiskEntry] = [
    # --- LLM Hallucination Risks ---
    RiskEntry(
        id="R-001",
        category="LLM Hallucination",
        title="False vulnerability report",
        description=(
            "The LLM fabricates a vulnerability that does not exist in the "
            "target binary. This could cause wasted remediation effort or "
            "false confidence in the tool's output."
        ),
        severity="high",
        likelihood="medium",
        impact="Wasted triage effort; erosion of trust in the tool",
        mitigation=(
            "Summarizer system prompt explicitly prohibits fabrication. "
            "Structured findings are cross-referenced against raw tool output. "
            "Fallback rule-based summarizer provides ground truth."
        ),
        residual_risk="LLM may still overstate confidence in ambiguous findings",
    ),
    RiskEntry(
        id="R-002",
        category="LLM Hallucination",
        title="Misclassified vulnerability type",
        description=(
            "The LLM correctly identifies a vulnerability exists but assigns "
            "the wrong class (e.g., labels a format string as a buffer overflow)."
        ),
        severity="medium",
        likelihood="medium",
        impact="Incorrect remediation guidance; wrong exploitation path",
        mitigation=(
            "Disassembler skill uses pattern matching (not LLM) for primary "
            "classification. LLM summary is supplementary, not authoritative."
        ),
        residual_risk="Edge cases where multiple vuln classes overlap",
    ),

    # --- Scope Escalation Risks ---
    RiskEntry(
        id="R-003",
        category="Scope Escalation",
        title="Agent scans unauthorized targets",
        description=(
            "The LLM planner selects network_scan with a target outside the "
            "authorized scope, potentially scanning production systems."
        ),
        severity="critical",
        likelihood="low",
        impact="Unauthorized network reconnaissance; legal liability",
        mitigation=(
            "Target IP is validated by the nmap_runner before execution. "
            "Planner system prompt restricts to authorized testing. "
            "Context injection would require compromising the local LLM."
        ),
        residual_risk=(
            "Validation only checks IP format, not authorization. "
            "A scope allowlist would further reduce risk."
        ),
    ),
    RiskEntry(
        id="R-004",
        category="Scope Escalation",
        title="Agent executes beyond analysis",
        description=(
            "The agent attempts to exploit a vulnerability rather than just "
            "analyzing it — e.g., generating and running a payload."
        ),
        severity="critical",
        likelihood="low",
        impact="Unauthorized code execution on target; potential damage",
        mitigation=(
            "No exploitation skills are registered. The skill registry is "
            "a hard boundary — the agent cannot execute skills that don't exist. "
            "Tool wrappers (GDB, objdump) are read-only analysis tools."
        ),
        residual_risk=(
            "A future developer could add an exploitation skill without "
            "adequate review. Code review and access control are essential."
        ),
    ),

    # --- Tool Misuse Risks ---
    RiskEntry(
        id="R-005",
        category="Tool Misuse",
        title="Command injection via binary path",
        description=(
            "An attacker crafts a binary path containing shell metacharacters "
            "that get executed by subprocess calls."
        ),
        severity="high",
        likelihood="low",
        impact="Arbitrary command execution on the analysis machine",
        mitigation=(
            "All tool wrappers use subprocess with list arguments (not shell=True). "
            "Binary paths are validated with os.path.isfile() before use. "
            "GDB commands are written to temp files, not interpolated into shell."
        ),
        residual_risk="Minimal — subprocess list mode prevents injection",
    ),
    RiskEntry(
        id="R-006",
        category="Tool Misuse",
        title="Resource exhaustion via large binary",
        description=(
            "Analyzing a very large binary causes objdump/GDB to consume "
            "excessive memory or CPU, potentially crashing the analysis host."
        ),
        severity="medium",
        likelihood="medium",
        impact="Denial of service on the analysis machine",
        mitigation=(
            "All subprocess calls have timeout parameters. "
            "GDB runs with a 30-second default timeout. "
            "objdump output is parsed incrementally."
        ),
        residual_risk="Timeout may not prevent memory exhaustion in all cases",
    ),

    # --- Autonomy Risks ---
    RiskEntry(
        id="R-007",
        category="Autonomy",
        title="Unbounded agent loop",
        description=(
            "The planner LLM never selects 'done', causing the agent to "
            "loop indefinitely through skills without converging."
        ),
        severity="medium",
        likelihood="medium",
        impact="Wasted compute; no useful output; potential infinite loop",
        mitigation=(
            "run_chain() has a hard max_steps limit (default: 5). "
            "The chain prompt explicitly tells the planner to finish when "
            "all relevant skills have been used."
        ),
        residual_risk="Agent may exhaust all steps without meaningful progress",
    ),
    RiskEntry(
        id="R-008",
        category="Autonomy",
        title="Planner selects wrong skill order",
        description=(
            "The LLM chooses an inefficient or illogical skill sequence "
            "(e.g., disassembling before checking if the binary exists)."
        ),
        severity="low",
        likelihood="medium",
        impact="Wasted steps; less efficient analysis",
        mitigation=(
            "Chain prompt includes guidance on logical skill ordering. "
            "Keyword fallback provides a deterministic ordering when LLM fails. "
            "Each skill validates its own inputs before execution."
        ),
        residual_risk="LLM may still make suboptimal ordering choices",
    ),

    # --- Data Handling Risks ---
    RiskEntry(
        id="R-009",
        category="Data Handling",
        title="Sensitive data in memory / logs",
        description=(
            "The agent's memory manager and trace logs may contain sensitive "
            "information from the target (passwords, keys, PII)."
        ),
        severity="medium",
        likelihood="medium",
        impact="Information disclosure if logs are shared or stored insecurely",
        mitigation=(
            "Memory is in-process only — not persisted to disk by default. "
            "Summarizer compresses raw output, reducing retained detail. "
            "No data is sent to external services (local LLM only)."
        ),
        residual_risk="Demo scripts print memory to stdout, which may be logged",
    ),
    RiskEntry(
        id="R-010",
        category="Data Handling",
        title="LLM training data leakage",
        description=(
            "The local LLM may have memorized vulnerability details or "
            "exploit code from its training data, which could surface in "
            "agent outputs."
        ),
        severity="low",
        likelihood="low",
        impact="Unintended disclosure of exploit techniques",
        mitigation=(
            "System prompts instruct the LLM to focus on analysis only. "
            "Summarizer validates outputs against actual tool data. "
            "Local model has no internet access to retrieve new exploits."
        ),
        residual_risk="Training data memorization is inherent to LLMs",
    ),
]


# ---------------------------------------------------------------------------
# Guardrails — runtime safety checks
# ---------------------------------------------------------------------------

class SafetyGuardrails:
    """
    Runtime safety checks that run before and after skill execution.

    These are defense-in-depth measures beyond what individual tools enforce.
    """

    # Paths that should never be analyzed (system binaries)
    BLOCKED_PATHS = [
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/System/", "/Library/",
    ]

    # Maximum binary size to analyze (100 MB)
    MAX_BINARY_SIZE = 100 * 1024 * 1024

    def __init__(self) -> None:
        self.audit_log: list[dict] = []

    def check_binary_path(self, path: str) -> tuple[bool, str]:
        """Verify that a binary path is safe to analyze."""
        abs_path = os.path.abspath(path)

        # Block system paths
        for blocked in self.BLOCKED_PATHS:
            if abs_path.startswith(blocked):
                self._audit("BLOCKED", f"System path: {abs_path}")
                return False, f"Blocked: system binary at {blocked}"

        # Check file size
        if os.path.isfile(abs_path):
            size = os.path.getsize(abs_path)
            if size > self.MAX_BINARY_SIZE:
                self._audit("BLOCKED", f"Binary too large: {size} bytes")
                return False, f"Binary too large: {size} bytes (max {self.MAX_BINARY_SIZE})"

        self._audit("ALLOWED", f"Binary path OK: {abs_path}")
        return True, "OK"

    def check_target_ip(self, ip: str) -> tuple[bool, str]:
        """Verify that a scan target is in a safe range."""
        # Allow localhost and private ranges
        safe_prefixes = [
            "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.",
        ]

        if any(ip.startswith(p) for p in safe_prefixes):
            self._audit("ALLOWED", f"Target IP in safe range: {ip}")
            return True, "OK"

        self._audit("WARNING", f"Target IP not in private range: {ip}")
        return True, f"WARNING: {ip} is not a private IP — ensure authorization"

    def check_skill_arguments(
        self, skill_name: str, arguments: dict
    ) -> tuple[bool, str]:
        """Pre-execution check on skill arguments."""
        if skill_name in ("gdb_debug", "disassemble"):
            binary_path = arguments.get("binary_path", "")
            if binary_path:
                return self.check_binary_path(binary_path)

        if skill_name == "network_scan":
            target_ip = arguments.get("target_ip", "")
            if target_ip:
                return self.check_target_ip(target_ip)

        self._audit("ALLOWED", f"No specific checks for {skill_name}")
        return True, "OK"

    def validate_output(
        self, skill_name: str, result: dict
    ) -> list[str]:
        """Post-execution validation of skill output."""
        warnings = []

        # Check for potential hallucination indicators
        if skill_name == "disassemble" and result.get("success"):
            data = result.get("data", {})
            vulns = data.get("vulnerability_patterns", [])
            dangerous = data.get("dangerous_calls", [])

            # Warn if vulnerabilities claimed but no dangerous calls found
            if vulns and not dangerous:
                warnings.append(
                    "WARNING: Vulnerability patterns reported but no "
                    "dangerous function calls found — verify manually"
                )

        return warnings

    def get_audit_log(self) -> list[dict]:
        """Return the full audit log."""
        return self.audit_log

    def _audit(self, action: str, detail: str) -> None:
        """Record an audit entry."""
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
        })


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_risk_report(include_taxonomy: bool = True) -> str:
    """Generate a formatted risk analysis report."""
    lines = []
    lines.append("=" * 70)
    lines.append("  SAFETY AND RISK ANALYSIS")
    lines.append("  Autonomous Offensive Security Agent")
    lines.append("=" * 70)

    lines.append("\n1. EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(
        "This system is an LLM-driven security analysis agent that autonomously\n"
        "orchestrates vulnerability discovery tools (GDB, objdump, nmap). While\n"
        "designed for authorized defensive testing, the autonomous nature of the\n"
        "system introduces risks that must be understood and mitigated.\n"
    )
    lines.append("Key risk areas:")
    lines.append("  - LLM hallucination: false or misclassified vulnerabilities")
    lines.append("  - Scope escalation: agent acting beyond authorized targets")
    lines.append("  - Tool misuse: command injection or resource exhaustion")
    lines.append("  - Autonomy: unbounded loops or wrong skill ordering")
    lines.append("  - Data handling: sensitive information in logs/memory")

    lines.append("\n2. ARCHITECTURAL SAFEGUARDS")
    lines.append("-" * 40)
    lines.append(
        "The system implements defense-in-depth through multiple layers:\n"
        "\n"
        "  a) Skill Registry Boundary\n"
        "     The agent can ONLY execute registered skills. No exploitation\n"
        "     skills exist — only analysis (GDB debug, disassembly, scanning).\n"
        "     Adding new skills requires code changes and review.\n"
        "\n"
        "  b) Input Validation\n"
        "     Every tool wrapper validates inputs before subprocess execution.\n"
        "     IPs are parsed, paths are canonicalized, and subprocess uses\n"
        "     list arguments (not shell=True) to prevent injection.\n"
        "\n"
        "  c) Timeout Enforcement\n"
        "     All subprocess calls have configurable timeouts to prevent\n"
        "     resource exhaustion (GDB: 30s, nmap: 120s, objdump: 30s).\n"
        "\n"
        "  d) Local-Only LLM\n"
        "     All LLM inference runs on a local Ollama instance. No data\n"
        "     leaves the machine. No API keys. No cloud dependencies.\n"
        "\n"
        "  e) Fallback Behavior\n"
        "     When the LLM is unavailable, the system falls back to\n"
        "     deterministic keyword matching and rule-based summarization.\n"
        "     This ensures the pipeline never depends solely on LLM judgment.\n"
        "\n"
        "  f) Chain Step Limits\n"
        "     Multi-step chains have a hard maximum (default: 5 steps).\n"
        "     The agent cannot loop indefinitely.\n"
    )

    lines.append("\n3. FAILURE MODES")
    lines.append("-" * 40)
    lines.append(
        "  Mode 1: LLM Unavailable\n"
        "    Trigger:  Ollama not running or model not pulled\n"
        "    Behavior: Falls back to keyword planner + rule-based summarizer\n"
        "    Impact:   Reduced intelligence but functional pipeline\n"
        "    Status:   HANDLED\n"
        "\n"
        "  Mode 2: Binary Crashes GDB\n"
        "    Trigger:  Target binary triggers GDB bug or anti-debug\n"
        "    Behavior: Subprocess timeout kills GDB; error returned\n"
        "    Impact:   Incomplete crash analysis for that binary\n"
        "    Status:   HANDLED\n"
        "\n"
        "  Mode 3: LLM Hallucinates Skill\n"
        "    Trigger:  Planner returns a skill name that doesn't exist\n"
        "    Behavior: Registry lookup fails; agent reports 'skill not registered'\n"
        "    Impact:   Wasted step in the chain\n"
        "    Status:   HANDLED\n"
        "\n"
        "  Mode 4: Adversarial Binary\n"
        "    Trigger:  Binary detects GDB (ptrace check) and changes behavior\n"
        "    Behavior: Analysis may miss the real vulnerability\n"
        "    Impact:   False negative — vulnerability exists but not found\n"
        "    Status:   NOT HANDLED (out of scope for this prototype)\n"
    )

    if include_taxonomy:
        lines.append("\n4. RISK TAXONOMY")
        lines.append("-" * 40)

        by_category: dict[str, list[RiskEntry]] = {}
        for risk in RISK_TAXONOMY:
            by_category.setdefault(risk.category, []).append(risk)

        for category, risks in by_category.items():
            lines.append(f"\n  [{category}]")
            for risk in risks:
                lines.append(f"\n    {risk.id}: {risk.title}")
                lines.append(f"    Severity: {risk.severity} | Likelihood: {risk.likelihood}")
                lines.append(f"    {risk.description}")
                lines.append(f"    Impact: {risk.impact}")
                lines.append(f"    Mitigation: {risk.mitigation}")
                lines.append(f"    Residual: {risk.residual_risk}")

    lines.append(f"\n{'=' * 70}")
    lines.append("  END OF RISK ANALYSIS")
    lines.append(f"{'=' * 70}")

    return "\n".join(lines)


def risk_summary_json() -> dict[str, Any]:
    """Return a machine-readable risk summary."""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for risk in RISK_TAXONOMY:
        by_severity[risk.severity] = by_severity.get(risk.severity, 0) + 1
        by_category[risk.category] = by_category.get(risk.category, 0) + 1

    return {
        "total_risks": len(RISK_TAXONOMY),
        "by_severity": by_severity,
        "by_category": by_category,
        "risks": [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "severity": r.severity,
                "likelihood": r.likelihood,
            }
            for r in RISK_TAXONOMY
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Safety and risk analysis report")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--short", action="store_true", help="Skip risk taxonomy details")
    args = parser.parse_args()

    if args.json:
        print(json.dumps(risk_summary_json(), indent=2))
    else:
        print(generate_risk_report(include_taxonomy=not args.short))


if __name__ == "__main__":
    main()
