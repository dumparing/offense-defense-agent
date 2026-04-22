"""
memory_manager.py — Structured state management for multi-step agent sessions.

The MemoryManager keeps a running record of:
    - The current target being assessed
    - Discovered open ports and services
    - Key findings from each step
    - Actions attempted and their outcomes
    - Condensed history summaries (to avoid context bloat)

Design goals:
    - Keep the context window small by summarizing rather than accumulating
    - Provide a clean snapshot the planner LLM can consume each turn
    - Make it easy to serialize for logging / display
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ActionRecord:
    """A single action the agent performed."""
    skill: str
    arguments: dict[str, Any]
    success: bool
    summary: str
    timestamp: str = field(default_factory=lambda: _now())


@dataclass
class MemoryManager:
    """
    Structured state store for an agent session.

    The planner LLM receives get_context_snapshot() each turn so it knows
    what has already been discovered without re-reading raw tool output.
    """

    # Target information
    current_target: str | None = None

    # Discovered network state
    discovered_open_ports: list[int] = field(default_factory=list)
    discovered_services: dict[str, str] = field(default_factory=dict)

    # Binary analysis state
    analyzed_binaries: dict[str, dict] = field(default_factory=dict)
    crash_data: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)

    # High-level findings (short sentences)
    findings: list[str] = field(default_factory=list)

    # Action log
    attempted_actions: list[ActionRecord] = field(default_factory=list)

    # Condensed history — LLM-generated summaries of past steps
    condensed_history: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def record_action(
        self,
        skill: str,
        arguments: dict[str, Any],
        success: bool,
        summary: str,
    ) -> None:
        """Log that an action was attempted."""
        self.attempted_actions.append(
            ActionRecord(
                skill=skill,
                arguments=arguments,
                success=success,
                summary=summary,
            )
        )

    def record_scan_results(
        self,
        target: str,
        open_ports: list[int],
        services: dict[str, str],
    ) -> None:
        """Merge scan results into the memory state."""
        self.current_target = target

        # Merge ports (deduplicate)
        for port in open_ports:
            if port not in self.discovered_open_ports:
                self.discovered_open_ports.append(port)
        self.discovered_open_ports.sort()

        # Merge services
        self.discovered_services.update(services)

    def record_findings(self, new_findings: list[str]) -> None:
        """Add high-level finding sentences."""
        for f in new_findings:
            if f not in self.findings:
                self.findings.append(f)

    def record_crash(
        self,
        binary: str,
        signal: str | None,
        fault_address: str | None,
        backtrace: list[str],
        input_label: str = "",
    ) -> None:
        """Record crash information from GDB debugging."""
        self.crash_data.append({
            "binary": binary,
            "signal": signal,
            "fault_address": fault_address,
            "backtrace": backtrace[:5],
            "input_label": input_label,
        })

    def record_binary_analysis(
        self,
        binary: str,
        arch: dict | None = None,
        protections: dict | None = None,
        dangerous_calls: list | None = None,
        vulnerability_patterns: list | None = None,
        risk_level: str | None = None,
    ) -> None:
        """Record disassembly / binary analysis findings."""
        self.analyzed_binaries[binary] = {
            "architecture": arch,
            "protections": protections,
            "dangerous_calls_count": len(dangerous_calls or []),
            "risk_level": risk_level,
        }
        for pattern in (vulnerability_patterns or []):
            vuln = {
                "binary": binary,
                "vulnerability": pattern.get("vulnerability"),
                "confidence": pattern.get("confidence"),
                "description": pattern.get("description"),
            }
            if vuln not in self.vulnerabilities:
                self.vulnerabilities.append(vuln)

    def record_summary(self, summary: str) -> None:
        """Append a condensed history entry (LLM-generated summary of a step)."""
        self.condensed_history.append(summary)

    # ------------------------------------------------------------------
    # Snapshot for the planner
    # ------------------------------------------------------------------

    def get_context_snapshot(self) -> dict[str, Any]:
        """
        Return a concise dict the planner LLM consumes each turn.

        This is intentionally kept small so it fits comfortably in the
        model's context window alongside the skill catalog and task.
        """
        return {
            "current_target": self.current_target,
            "discovered_open_ports": self.discovered_open_ports,
            "discovered_services": self.discovered_services,
            "analyzed_binaries": self.analyzed_binaries,
            "crash_data": self.crash_data,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "actions_taken": [
                {
                    "skill": a.skill,
                    "success": a.success,
                    "summary": a.summary,
                }
                for a in self.attempted_actions
            ],
            "condensed_history": self.condensed_history,
        }

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize the full memory state to JSON."""
        return json.dumps(self.get_context_snapshot(), indent=indent, default=str)

    def __repr__(self) -> str:
        n_actions = len(self.attempted_actions)
        n_ports = len(self.discovered_open_ports)
        return (
            f"<MemoryManager target={self.current_target!r} "
            f"ports={n_ports} actions={n_actions}>"
        )


def _now() -> str:
    """ISO-formatted UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
