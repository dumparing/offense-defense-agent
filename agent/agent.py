"""
agent.py — LLM-driven agent loop with local Llama planner.

This module implements the core "reason → act → observe" cycle:
    1. Receive a natural-language task from the user.
    2. Read the current memory snapshot (what we already know).
    3. Ask the local Llama planner which skill to use and with what arguments.
    4. Execute the chosen skill.
    5. Summarize/compress the raw output via the summarizer.
    6. Update structured memory with the new findings.
    7. Return a clean result object with full decision trace.

The planner uses a local Llama model via Ollama, keeping all data on-machine.
If Ollama is unavailable, the agent falls back to keyword-based skill selection
so the demo still works without a running model.
"""

from __future__ import annotations

import json
import re
from typing import Any

from core.llm_client import LLMClient, OllamaError
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from core.summarizer import Summarizer


# ---------------------------------------------------------------------------
# Planner system prompt
# ---------------------------------------------------------------------------

PLANNER_SYSTEM = (
    "You are a defensive cybersecurity agent planner. Your job is to select "
    "the best skill to execute for a given task. You operate in an AUTHORIZED "
    "testing environment only.\n\n"
    "Rules:\n"
    "- Choose exactly one skill from the available list.\n"
    "- Extract the required arguments from the task and context.\n"
    "- Respond with ONLY valid JSON, no markdown, no explanation.\n"
    "- Do NOT suggest exploitation or unauthorized actions.\n"
    "- If no skill fits, set skill to \"none\".\n"
)


# ---------------------------------------------------------------------------
# Keyword fallback (used when Ollama is unavailable)
# ---------------------------------------------------------------------------

KEYWORD_SKILL_MAP: dict[str, list[str]] = {
    "network_scan": [
        "scan", "port", "service", "nmap", "recon", "reconnaissance",
    ],
}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SecurityAgent:
    """
    LLM-driven agent loop for authorized defensive security testing.

    Architecture:
        User Task
            ↓
        [Memory Snapshot] — what do we already know?
            ↓
        [Planner LLM]    — which skill should we use?
            ↓
        [Skill Execution] — run the chosen skill
            ↓
        [Summarizer]      — compress raw output
            ↓
        [Memory Update]   — store structured findings
            ↓
        Result + Trace
    """

    def __init__(
        self,
        registry: SkillRegistry,
        memory: MemoryManager | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self.registry = registry
        self.memory = memory or MemoryManager()
        self.llm = llm or LLMClient()
        self.summarizer = Summarizer(self.llm)
        # Decision trace — records every step for observability
        self.trace: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, task: str, context: dict[str, Any] | None = None) -> dict:
        """
        Execute one full agent turn for a given task.

        Args:
            task:    Natural-language task description.
            context: Optional dict with pre-extracted parameters
                     (e.g. {"target_ip": "192.168.1.1"}).

        Returns:
            Dict with: success, summary, skill_result, summarized_result,
                       memory_snapshot, and full decision trace.
        """
        context = context or {}
        self._log("task_received", {"task": task, "context": context})

        # --- Step 1: Read current memory ---
        memory_snapshot = self.memory.get_context_snapshot()
        self._log("memory_read", {"snapshot": memory_snapshot})

        # --- Step 2: Ask planner LLM which skill to use ---
        plan = self._plan(task, context, memory_snapshot)
        skill_name = plan.get("skill")
        arguments = plan.get("arguments", {})
        reasoning = plan.get("reasoning_summary", "")

        self._log("planner_decision", {
            "skill": skill_name,
            "arguments": arguments,
            "reasoning": reasoning,
        })

        # Validate: does this skill exist?
        if not skill_name or skill_name == "none":
            self._log("no_skill_selected", {"reasoning": reasoning})
            return self._result(
                success=False,
                summary="The planner could not find a matching skill for this task.",
                reasoning=reasoning,
            )

        skill = self.registry.get(skill_name)
        if skill is None:
            self._log("skill_not_registered", {"skill": skill_name})
            return self._result(
                success=False,
                summary=f"Planner selected '{skill_name}', but it is not registered.",
                reasoning=reasoning,
            )

        # --- Step 3: Merge context into arguments ---
        # The planner may have extracted args; context overrides them
        merged_args = {**arguments, **context}
        self._log("executing_skill", {"skill": skill_name, "arguments": merged_args})

        # --- Step 4: Execute the skill ---
        skill_result = skill.execute(**merged_args)
        self._log("skill_result", {"success": skill_result.get("success"), "brief": _brief(skill_result)})

        # --- Step 5: Summarize / compress the output ---
        summarized = self.summarizer.summarize_generic(skill_name, skill_result)
        nl_summary = summarized.get("natural_language_summary", "")
        structured = summarized.get("structured", {})
        self._log("summarized", {"summary": nl_summary, "structured_keys": list(structured.keys())})

        # --- Step 6: Update memory ---
        self.memory.record_action(
            skill=skill_name,
            arguments=merged_args,
            success=skill_result.get("success", False),
            summary=nl_summary,
        )

        # Skill-specific memory updates
        if skill_name == "network_scan" and skill_result.get("success"):
            self.memory.record_scan_results(
                target=merged_args.get("target_ip", "unknown"),
                open_ports=structured.get("open_ports", []),
                services=structured.get("services", {}),
            )

        if structured.get("findings"):
            self.memory.record_findings(structured["findings"])

        self.memory.record_summary(nl_summary)

        updated_snapshot = self.memory.get_context_snapshot()
        self._log("memory_updated", {"snapshot": updated_snapshot})

        # --- Step 7: Return clean result ---
        return self._result(
            success=skill_result.get("success", False),
            summary=nl_summary,
            reasoning=reasoning,
            skill_used=skill_name,
            skill_arguments=merged_args,
            skill_result=skill_result,
            summarized_result=summarized,
            memory_snapshot=updated_snapshot,
        )

    # ------------------------------------------------------------------
    # Planner — LLM-based skill selection
    # ------------------------------------------------------------------

    def _plan(
        self,
        task: str,
        context: dict[str, Any],
        memory: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Ask the local Llama model to choose a skill and extract arguments.

        Falls back to keyword matching if Ollama is unavailable.
        """
        skills_catalog = self.registry.list_skills()

        prompt = (
            f"TASK: {task}\n\n"
            f"CONTEXT: {json.dumps(context)}\n\n"
            f"CURRENT MEMORY STATE:\n{json.dumps(memory, indent=2)}\n\n"
            f"AVAILABLE SKILLS:\n{json.dumps(skills_catalog, indent=2)}\n\n"
            "Select the best skill for this task. "
            "Respond with ONLY this JSON format:\n"
            "{\n"
            '  "skill": "skill_name",\n'
            '  "arguments": {"arg1": "value1"},\n'
            '  "reasoning_summary": "Why you chose this skill"\n'
            "}\n\n"
            "If no skill applies, set skill to \"none\".\n"
        )

        try:
            plan = self.llm.generate_json(prompt, system_prompt=PLANNER_SYSTEM)
            self._log("planner_llm_used", {"model": self.llm.model})
            return plan
        except OllamaError as exc:
            # Fall back to keyword matching
            self._log("planner_llm_fallback", {"reason": str(exc)})
            return self._keyword_fallback(task, context)

    def _keyword_fallback(
        self, task: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Simple keyword-based skill selection (fallback when LLM is unavailable).
        Preserves the original behavior so the demo works without Ollama.
        """
        task_lower = task.lower()
        best_skill = None
        best_score = 0

        for skill_name, keywords in KEYWORD_SKILL_MAP.items():
            score = sum(1 for kw in keywords if kw in task_lower)
            if score > best_score:
                best_score = score
                best_skill = skill_name

        # Try to extract target_ip from task or context
        arguments: dict[str, Any] = {}
        if "target_ip" in context:
            arguments["target_ip"] = context["target_ip"]
        else:
            ip_match = re.search(
                r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", task
            )
            if ip_match:
                arguments["target_ip"] = ip_match.group()

        return {
            "skill": best_skill or "none",
            "arguments": arguments,
            "reasoning_summary": (
                f"[Keyword fallback] Matched '{best_skill}' with score {best_score}. "
                "LLM planner was unavailable."
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, event: str, data: dict[str, Any]) -> None:
        """Append an entry to the agent's decision trace."""
        self.trace.append({"event": event, **data})

    def _result(self, **kwargs: Any) -> dict[str, Any]:
        """Build the final result dict, attaching the full trace."""
        return {**kwargs, "trace": self.trace}


def _brief(result: dict) -> dict:
    """Return a shortened version of a skill result (omit raw output for logging)."""
    brief = {k: v for k, v in result.items() if k != "data"}
    data = result.get("data")
    if isinstance(data, dict):
        brief["services_found"] = data.get("services_found")
    return brief
