"""
agent.py — The core agent loop.

This module implements a minimal "reason → act → observe" agent that:
    1. Accepts a natural-language task from the user.
    2. Examines available skills and selects the best match.
    3. Extracts required parameters from the task context.
    4. Executes the chosen skill.
    5. Summarizes the results and decides whether more steps are needed.

In a full implementation the reasoning steps would be handled by an LLM
(e.g. Claude). This prototype uses simple keyword matching to demonstrate
the architecture without requiring API keys.
"""

from __future__ import annotations

import re
from typing import Any

from core.skill_registry import SkillRegistry


# ---------------------------------------------------------------------------
# Keyword map: maps task keywords → skill names.
# In production this would be replaced by LLM-based intent classification.
# ---------------------------------------------------------------------------
KEYWORD_SKILL_MAP: dict[str, List[str]] = {
    "network_scan": ["scan", "port", "service", "nmap", "recon", "reconnaissance"],
    # Future skills would be added here:
    # "sql_injection": ["sqli", "sql", "injection", "database"],
    # "exploit":       ["exploit", "metasploit", "payload", "shell"],
}


class SecurityAgent:
    """
    Minimal agent loop for LLM-driven security testing.

    Architecture:
        User Task
            ↓
        [Reason] — pick a skill (keyword match / LLM)
            ↓
        [Act]    — execute the skill
            ↓
        [Observe] — read results, summarize, decide next step
    """

    def __init__(self, registry: SkillRegistry) -> None:
        self.registry = registry
        # Conversation-style log so we can trace the agent's decisions
        self.trace: list[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, task: str, context: Dict[str, Any] | None = None) -> dict:
        """
        Execute the full agent loop for a given task.

        Args:
            task:    Natural-language task description.
            context: Optional dict with pre-extracted parameters
                     (e.g. {"target_ip": "192.168.1.1"}).

        Returns:
            A summary dict with the agent's trace and final answer.
        """
        context = context or {}
        self._log("task_received", {"task": task, "context": context})

        # --- Step 1: Reason — choose a skill ---
        skill_name = self._select_skill(task)
        if skill_name is None:
            self._log("no_skill_matched", {"task": task})
            return self._result(
                success=False,
                summary="No matching skill found for this task.",
            )

        skill = self.registry.get(skill_name)
        if skill is None:
            self._log("skill_not_registered", {"skill": skill_name})
            return self._result(
                success=False,
                summary=f"Skill '{skill_name}' is not registered.",
            )

        self._log("skill_selected", {"skill": skill_name})

        # --- Step 2: Extract parameters ---
        params = self._extract_params(skill, task, context)
        self._log("params_extracted", {"params": params})

        # --- Step 3: Act — execute the skill ---
        self._log("executing_skill", {"skill": skill_name, "params": params})
        result = skill.execute(**params)
        self._log("skill_result", {"result_summary": _brief(result)})

        # --- Step 4: Observe — summarize ---
        summary = self._summarize(skill_name, result)
        self._log("summary", {"text": summary})

        return self._result(
            success=result.get("success", False),
            summary=summary,
            skill_result=result,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_skill(self, task: str) -> str | None:
        """
        Match task text to a skill using keyword heuristics.

        In a production system this would call an LLM:
            "Given these skills: [...], which one best matches: <task>?"
        """
        task_lower = task.lower()
        best_skill = None
        best_score = 0

        for skill_name, keywords in KEYWORD_SKILL_MAP.items():
            score = sum(1 for kw in keywords if kw in task_lower)
            if score > best_score:
                best_score = score
                best_skill = skill_name

        return best_skill

    def _extract_params(
        self, skill, task: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build the parameter dict for a skill invocation.

        Priority:
            1. Values explicitly provided in `context`.
            2. Values extracted from the task string (e.g. IP addresses).
        """
        params: Dict[str, Any] = {}

        for field in skill.input_schema:
            if field in context:
                params[field] = context[field]
            elif field == "target_ip":
                # Try to pull an IP address from the task text
                ip_match = re.search(
                    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", task
                )
                if ip_match:
                    params["target_ip"] = ip_match.group()

        return params

    def _summarize(self, skill_name: str, result: dict) -> str:
        """
        Produce a human-readable summary of the skill result.

        In production an LLM would generate this. Here we use templates.
        """
        if not result.get("success"):
            return f"Skill '{skill_name}' failed: {result.get('error', 'unknown error')}"

        data = result.get("data", {})

        if skill_name == "network_scan":
            n = data.get("services_found", 0)
            target = data.get("target", "unknown")
            lines = [f"Scan of {target} found {n} open service(s)."]
            for svc in data.get("services", []):
                lines.append(
                    f"  - {svc['port']}/{svc['protocol']} "
                    f"{svc['state']} {svc['service']} {svc['version']}"
                )
            return "\n".join(lines)

        return f"Skill '{skill_name}' completed successfully."

    def _log(self, event: str, data: dict) -> None:
        """Append an entry to the agent's decision trace."""
        self.trace.append({"event": event, **data})

    def _result(self, **kwargs) -> dict:
        """Build the final result dict, attaching the full trace."""
        return {**kwargs, "trace": self.trace}


def _brief(result: dict) -> dict:
    """Return a shortened version of a skill result (omit raw output)."""
    brief = {k: v for k, v in result.items() if k != "data"}
    data = result.get("data")
    if isinstance(data, dict):
        brief["services_found"] = data.get("services_found")
    return brief
